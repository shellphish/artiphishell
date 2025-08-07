

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Dict, List

import git
import yaml
from enum import Enum

import json
import shutil
import logging

from shellphish_crs_utils.result_parsers import parse_pov_result

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
CACHED_BUILD_DIR = Path("/shared/target_build_cache")

@dataclass
class HarnessSpec:
    harness_id: str
    name: str
    source: str
    binary: str

class ChallengeProjectSource:
    def __init__(self, key, data):
        self.key = key
        self.data = data

    @property
    def source_git_repo_address(self):
        return self.data['address']

    @property
    def git_ref(self):
        return self.data['ref']

    @property
    def artifacts(self):
        return self.data['artifacts']

    @property
    def cp_relative_dir(self) -> Path:
        if 'directory' in self.data:
            return Path(self.data['directory'])
        else:
            return Path('src') / self.key

class ChallengeProject:
    def __init__(self, path: Path, cp_version = None):
        self.project_path = Path(path)
        assert (self.project_path / 'project.yaml').exists(), f"Project file {self.project_path / 'project.yaml'} does not exist"
        assert (self.project_path / 'run.sh').exists(), f"Run script {self.project_path / 'run.sh'} does not exist"
        assert (self.project_path / 'Dockerfile').exists(), f"Dockerfile {self.project_path / 'Dockerfile'} does not exist"

        self.meta = yaml.safe_load((self.project_path / 'project.yaml').read_text())

    @property
    def cp_sources(self):
        assert 'cp_address' not in self.meta, "cp_address is not supported in V2 projects"
        return [ChallengeProjectSource(key, value) for key, value in self.meta['cp_sources'].items()]

    @property
    def harnesses(self) -> List[HarnessSpec]:
        return [HarnessSpec(harness_id, data['name'], data['source'], data['binary']) for harness_id, data in self.meta['harnesses'].items()]

    @property
    def sanitizers(self) -> Dict[str, str]:
        return self.meta['sanitizers']

    def checkout_clean_sources(self):
        for source in self.cp_sources:
            cp_rel_dir = source.cp_relative_dir
            assert cp_rel_dir, f"cp_relative_dir is not defined for {source.key}"
            cp_dir = self.project_path / cp_rel_dir
            subprocess.check_output(['git', '-C', cp_dir, 'reset', '--hard', source.git_ref])

    def checkout_commit(self, commit_hash):
        result = {}
        self.checkout_clean_sources()
        for sources in self.cp_sources:
            cp_rel_dir = sources.cp_relative_dir
            assert cp_rel_dir, f"cp_relative_dir is not defined for {sources.key}"
            cp_dir = self.project_path / cp_rel_dir
            try:
                git.Repo(cp_dir).git.checkout(commit_hash)
                return sources, commit_hash
            except git.exc.GitCommandError as e:
                result[sources.key] = e.stderr
        else:
            raise Exception(f"Failed to checkout commit {commit_hash} for {sources.key}: {result}")

    def peek_commit(self, commit_hash):
        result = {}
        self.checkout_clean_sources()
        for sources in self.cp_sources:
            cp_rel_dir = sources.cp_relative_dir
            assert cp_rel_dir, f"cp_relative_dir is not defined for {sources.key}"
            cp_dir = self.project_path / cp_rel_dir
            try:
                repo = git.Repo(cp_dir)
                # Try to get the commit object by its SHA
                commit = repo.commit(commit_hash)
                return sources, commit
            except Exception as e:
                result[sources.key] = e
        else:
            raise Exception(f"Failed to find commit {commit_hash} for {sources.key}: {result}")

    def get_repo(self, source_key:str):
        for source in self.cp_sources:
            if source.key == source_key:
                return git.Repo(self.project_path / source.cp_relative_dir)
        else:
            raise Exception(f"Failed to find source {source_key}")

    def is_built(self):
        return (self.project_path / '.built').exists()

    def run_sh_command(self, command, *args, timeout=None):
        try:
            # proc = subprocess.Popen(['run.sh', command, *args], cwd=self.project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            full_command = ['/bin/bash', '-x', 'run.sh', command, *args]
            time_start = time.time()
            proc = subprocess.run(full_command, cwd=self.project_path, capture_output=True, timeout=timeout)
            run_sh_stdout = proc.stdout
            run_sh_stderr = proc.stderr
            time_end = time.time()
            dir_regex = 'mkdir\s+-?p?\s+([^\s]*/out/output/[0-9]+.[0-9]+--' + command + ')'
            match = re.search(dir_regex.encode(), run_sh_stderr)
            if not match:
                print("WARNING: Failed to find directory in stderr, trying to find it with a more general regex")
                print("===== STDERR:")
                print(run_sh_stderr.decode())
                print("===== END STDERR")

                match = re.search(b'[^\s]--' + command.encode(), run_sh_stderr)
                if match:
                    dir = Path(match.group(0).decode())
                else:
                    print("WARNING: failed to find directory at all in stderr, picking the latest one")

                    all_command_outputs = [f for f in os.listdir(self.project_path / 'out' / 'output') if f.endswith('--' + command)]
                    all_command_outputs = [(float(x.name.split('--')), x) for x in all_command_outputs]
                    all_command_outputs.sort(key=lambda x: x[0])
                    # pick the highest timestamp
                    match = all_command_outputs[-1][1]
                    dir = self.project_path / 'out' / 'output' / match
            else:
                dir = Path(match.group(1).decode())

            assert dir.exists(), f"Output directory {dir} does not exist"

            result = {}
            result['run_sh_stdout'] = run_sh_stdout
            result['run_sh_stderr'] = run_sh_stderr
            result['time_start'] = time_start
            result['time_end'] = time_end
            result['time_taken'] = time_end - time_start

            with open(dir / 'docker.cid', 'r') as f:
                result['cid'] = f.read().strip()
                assert result['cid'], "Failed to read docker container ID"

            with open(dir / 'exitcode', 'r') as f:
                result['exitcode'] = int(f.read().strip())

            with open(dir / 'stdout.log', 'rb') as f:
                result['stdout'] = f.read()

            with open(dir / 'stderr.log', 'rb') as f:
                result['stderr'] = f.read()

            return result

        except subprocess.TimeoutExpired as e:
            raise e

    def get_commit_hash(self, src_path):
        return git.Repo(src_path).head.commit.hexsha

    def rsync_dirs(self, src, dst):
        return subprocess.run(['/usr/bin/rsync', '-ra', '--delete', src.as_posix()+'/', dst.as_posix()]).returncode

    def build(self, patch=None, **kwargs):
        src_commit_hashes = ""
        for source in self.cp_sources:
            src_commit_hashes += self.get_commit_hash(self.project_path / source.cp_relative_dir)
        if patch:
            src_commit_hashes += hashlib.sha256(patch.encode()).hexdigest()
            target_commit_hash = hashlib.sha256(src_commit_hashes.encode()).hexdigest()
            cache_directory = CACHED_BUILD_DIR / self.meta['cp_name'] / target_commit_hash
            cache_directory_lock = cache_directory.with_suffix('.lock')

            while cache_directory_lock.exists():
                try:
                    created_time = os.path.getctime(cache_directory_lock)
                except OSError:
                    cache_directory_lock.unlink(missing_ok=True)

                cur_time = time.time()
                if cur_time - created_time > 300:
                    logger.warn(f"Lock file {cache_directory_lock} exists for more than 5 minutes. Removing it now")
                    cache_directory_lock.unlink(missing_ok=True)
                else:
                    raise Exception(f"Lukas told me to: {cur_time=} - {created_time=} = {cur_time-created_time}")

            if cache_directory.exists():
                logger.info("Copying built target from {}".format(cache_directory))
                self.rsync_dirs(cache_directory, self.project_path)

                with open(self.project_path / 'work'/ 'result.json', 'r') as f:
                    result = json.load(f)
            else:
                logger.info("Creating lock file {}".format(cache_directory_lock))
                cache_directory_lock.parent.mkdir(parents=True, exist_ok=True)
                cache_directory_lock.touch(exist_ok=False)

                with tempfile.TemporaryFile() as f:
                    f.write(patch.encode())
                    f.seek(0)
                    f.flush()
                    # return subprocess.check_output(['run.sh', 'build', f.name], cwd=self.project_path)
                    result = self.run_sh_command('build', f.name, **kwargs)
        else:
            target_commit_hash = hashlib.sha256(src_commit_hashes.encode()).hexdigest()
            cache_directory = CACHED_BUILD_DIR / self.meta['cp_name'] / target_commit_hash
            cache_directory_lock = cache_directory.with_suffix('.lock')

            while cache_directory_lock.exists():
                try:
                    created_time = os.path.getctime(cache_directory_lock)
                except OSError:
                    cache_directory_lock.unlink(missing_ok=True)

                cur_time = time.time()
                if cur_time - created_time > 300:
                    logger.warn(f"Lock file {cache_directory_lock} exists for more than 5 minutes. Removing it now")
                    cache_directory_lock.unlink(missing_ok=True)
                else:
                    raise Exception(f"Lukas told me to: {cur_time=} - {created_time=} = {cur_time-created_time}")

            if cache_directory.exists():
                logger.info("Copying built target from {}".format(cache_directory))
                self.rsync_dirs(cache_directory, self.project_path)

                with open(self.project_path / 'work'/ 'result.json', 'r') as f:
                    result = json.load(f)
            else:
                logger.info("Creating lock file {}".format(cache_directory_lock))
                cache_directory_lock.parent.mkdir(parents=True, exist_ok=True)
                cache_directory_lock.touch(exist_ok=False)

                result = self.run_sh_command('build', **kwargs)

        logger.info(f"Finished building: {result=}")
        if result['exitcode'] == 0:
            with open(self.project_path / '.built', 'w') as f:
                f.write(patch if patch else '')

            result_file = self.project_path / 'work' / 'result.json'
            if result_file.exists() is False:
                result_copy = {}
                for key in result:
                    if isinstance(result[key], bytes):
                        try:
                            result_copy[key] = result[key].decode()
                        except:
                            result_copy[key] = ""
                    else:
                        result_copy[key] = result[key]

                with open(self.project_path / 'work' / 'result.json', 'w') as f:
                    json.dump(result_copy, f, indent=4)

                logger.info("Caching built target to {}".format(cache_directory))
                shutil.copytree(self.project_path, cache_directory)

        cache_directory_lock.unlink(missing_ok=True)
        logger.info("Done")
        return result

    def run_pov(self, harness, *, data=None, data_file=None, **kwargs):
        assert data is None or type(data) is bytes
        assert data is None or data_file is None

        with tempfile.TemporaryFile() as f:
            if data:
                f.write(data)
                f.seek(0)
                f.flush()
                data_file = f.name

            result = self.run_sh_command('run_pov', data_file, harness, **kwargs)
            result['pov'] = parse_pov_result(result, sanitizers=self.sanitizers)
            return result

    def run_tests(self, **kwargs):
        # return subprocess.check_output(['run.sh', 'run_tests'], cwd=self.project_path)
        return self.run_sh_command('run_tests', **kwargs)

