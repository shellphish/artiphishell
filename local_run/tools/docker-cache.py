#! /usr/bin/env python3

import os
import sys
import hashlib
import time
import json
import subprocess
import shutil
import argparse
import yaml
import requests
from pathlib import Path
import fnmatch
import logging
from typing import List
from filelock import FileLock, Timeout

from contextlib import contextmanager

@contextmanager
def optional_filelock(lock_path, timeout=10, max_retries=3, retry_delay=0.1):
    """
    best-effort file lock. tries to acquire, but continues anyway if it can't.
    
    useful for resource optimizations where locking is preferred but not required.
    """
    retries = 0
    lock = FileLock(lock_path, timeout=timeout)
    
    while retries < max_retries:
        try:
            with lock:
                yield True  # indicates we got the lock
                return
        except Timeout:
            retries += 1
            if retries >= max_retries:
                break
            
            # attempt to remove potentially stale lock
            try:
                os.remove(lock_path)
                time.sleep(retry_delay)
            except:
                pass
    
    # couldn't get lock, but continue anyway
    yield False  # indicates we're proceeding without lock

logger = logging.getLogger('docker-cache')
handler = logging.StreamHandler()
logger.addHandler(handler)
if os.environ.get('DOCKER_CACHE_DEBUG', '0') == '1':
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

WORKER_API_URL = "https://shellphish-support-syndicate-workers.cf-a92.workers.dev/api/v1/crs/docker/cache"
WORKER_TOKEN = os.getenv('WORKER_TOKEN', None)

DOCKER_BINARY = os.getenv('DOCKER_BINARY', '/usr/bin/docker')
if 'local_run' in DOCKER_BINARY:
    raise Exception("DOCKER_BINARY is set to a local_run binary, this is not allowed as it will cause a recursive loop")

# This script works by computing a hash for a docker build command before actually executing the command. It can then check to see if the given hash exists within a registry.
# This makes it possible to skip building images when they have been built previously without relying on the flakiness of the docker build process.
# In addition it also supports directly importing these images into azure container registry via the az cli.

def hash_file_streaming(filepath, algorithm='sha1', chunk_size=65536):
    hasher = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_if_excluded_by_docker_ignore(rel_file_path: Path, docker_ignore_rules: List[str]) -> bool:
    # Convert path to string with forward slashes (Docker uses Unix-style paths)
    file_path_str = str(rel_file_path).replace('\\', '/')
    
    # Track if file is excluded (start with False - include by default)
    excluded = False
    
    for rule in docker_ignore_rules:
        rule = rule.strip()
        
        # Skip empty lines and comments
        if not rule or rule.startswith('#'):
            continue
            
        # Handle negation patterns (lines starting with !)
        is_negation = rule.startswith('!')
        if is_negation:
            rule = rule[1:]  # Remove the ! prefix
            
        # Skip if rule is empty after removing !
        if not rule:
            continue
            
        # Handle directory-only patterns (ending with /)
        is_directory_only = rule.endswith('/')
        if is_directory_only:
            rule = rule[:-1]  # Remove trailing /
            
        # Store original rule for Docker's ** behavior
        original_rule = rule
        
        # If pattern doesn't start with / or ./, treat it as if it starts with **/
        if not rule.startswith('/') and not rule.startswith('./'):
            rule = '**/' + rule
            
        # Remove leading / if present
        if rule.startswith('/'):
            rule = rule[1:]
            
        # Handle ** patterns by converting to appropriate glob patterns
        # Replace ** with a pattern that matches any number of path segments
        rule_parts = rule.split('/')
        glob_pattern = ''
        
        for i, part in enumerate(rule_parts):
            if part == '**':
                # ** should always become ** in glob patterns
                glob_pattern += '**'
            else:
                if i > 0:
                    glob_pattern += '/'
                glob_pattern += part
                
        # Check if the pattern matches
        matches = False
        
        # For Docker compatibility, we need to test both the ** pattern and the original pattern
        # because Python's fnmatch doesn't handle ** the same way as Docker
        patterns_to_test = [glob_pattern]
        
        # If the pattern starts with **, also test without the ** prefix
        # This handles Docker's behavior where **/pattern matches both pattern and dir/pattern
        if glob_pattern.startswith('**/'):
            patterns_to_test.append(glob_pattern[3:])  # Remove the **/ prefix
        
        for test_pattern in patterns_to_test:
            if is_directory_only:
                # For directory-only patterns, check if any parent directory matches
                path_parts = file_path_str.split('/')
                for i in range(len(path_parts)):
                    dir_path = '/'.join(path_parts[:i+1])
                    if fnmatch.fnmatch(dir_path, test_pattern):
                        matches = True
                        break
            else:
                # Check if the file path matches the pattern
                if fnmatch.fnmatch(file_path_str, test_pattern):
                    matches = True
                    break
                
                # Also check if any parent directory matches (for patterns like "node_modules")
                path_parts = file_path_str.split('/')
                for i in range(len(path_parts)):
                    partial_path = '/'.join(path_parts[:i+1])
                    if fnmatch.fnmatch(partial_path, test_pattern):
                        matches = True
                        break
            
            if matches:
                break
        
        if matches:
            if is_negation:
                excluded = False  # Negation pattern - include the file
            else:
                excluded = True   # Normal pattern - exclude the file
                
    return excluded

class DockerCache:
    def __init__(self,
        cache_registry: str,
        import_mode: bool = False,
        push_mode: bool = False,
        push_cache: bool = False,
        git_branch: str = None,
        only_check_mode: bool = False,
        must_download: bool = False
    ):
        self.cache_registry = cache_registry
        self.import_mode = import_mode
        self.push_mode = push_mode and not only_check_mode
        if push_mode and only_check_mode:
            raise Exception("DOCKER_ONLY_CHECK and --push cannot be used together")
        self.push_cache = push_cache and cache_registry is not None
        self.deployment_cache = Path(f'/tmp/docker-cache-for-deployment.json')
        self.local_daemon_cache = Path(f'/tmp/docker-cache-local-daemon.json')
        self.git_branch = git_branch
        if self.git_branch:
            self.git_branch = self.git_branch.replace('/', '')
        self.must_download = must_download
        self.only_check_mode = only_check_mode and not must_download

    def get_hash_for_base_image(self, base_image: str) -> str:
        # When we use a base image which we also build we will lookup its hash which we would have already computed before hand.
        raise NotImplementedError("Not implemented")

    def parse_docker_args(self, build_command: List[str]) -> dict:
        argp = argparse.ArgumentParser()
        
        # Dockerfile path
        argp.add_argument('-f', '--file', dest='dockerfile', default=None,
                         help='Name of the Dockerfile')
        
        # Image tags
        argp.add_argument('-t', '--tag', dest='tags', action='append', default=[],
                         help='Name and optionally a tag in the name:tag format')
        
        # Build arguments
        argp.add_argument('--build-arg', dest='build_args', action='append', default=[],
                         help='Set build-time variables')

        # Target stage for multi-stage builds
        argp.add_argument('--target', dest='target', 
                         help='Set the target build stage to build')
        
        # Other common flags
        argp.add_argument('--no-cache', dest='no_cache', action='store_true',
                         help='Do not use cache when building the image')
        
        argp.add_argument('--pull', dest='pull', action='store_true',
                         help='Always attempt to pull a newer version of the image')

        argp.add_argument('--push', dest='push', action='store_true',
                         help='Push the image to the cache registry')
        
        argp.add_argument('--squash', dest='squash', action='store_true',
                         help='Squash newly built layers into a single new layer')

        argp.add_argument('--dry-run', dest='dry_run', action='store_true',
                         help='Do not actually build the image, just print the command')
        
        # Build context (positional argument, usually last)
        argp.add_argument('context', nargs='?', default='.',
                         help='Build context directory')

        argp.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                         help='Suppress output')
        
        # Parse the arguments
        args, unknown_args = argp.parse_known_args(build_command)
        
        # Add unknown arguments to the args object
        args.unknown_args = unknown_args

        if args.build_args:
            args.build_args = {
                v.split('=',1)[0]: v.split('=',1)[-1]
                for v in args.build_args
                if '=' in v
            }

        if not args.context:
            args.context = '.'
        args.context = Path(args.context)

        if not args.dockerfile:
            args.dockerfile = args.context / 'Dockerfile'
        args.dockerfile = Path(args.dockerfile)

        docker_ignore_path = args.context / '.dockerignore'
        if docker_ignore_path.exists():
            args.docker_ignore_rules = docker_ignore_path.read_text().strip().splitlines()
        else:
            args.docker_ignore_rules = []
        
        return args
        
    def parse_dockerfile(self, args) -> List[Path]:
        dockerfile = args.dockerfile
        build_context = args.context

        dependent_images = []
        in_scope_files = set()
        
        # Iterate over all lines in the dockerfile
        lines_iter = iter(enumerate(dockerfile.read_text().splitlines(), 1))
        
        for line_num, line in lines_iter:
            original_line = line
            line = line.strip()

            logger.debug(f"Line {line_num}: {line}")

            # If the line starts with a comment, skip it
            if line.startswith('#'):
                continue

            # If the line is empty, skip it
            if not line.strip():
                continue

            # Handle line continuations (backslash at end)
            while line.endswith('\\'):
                try:
                    next_line_num, next_line = next(lines_iter)
                    line = line[:-1] + ' ' + next_line.strip()
                except StopIteration:
                    break

            # Split into verb and arguments
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
                
            verb = parts[0].lower()
            args_str = parts[1]

            if verb in ['add', 'copy']:
                try:
                    sources = self._parse_add_copy_instruction(args, args_str, build_context)
                    in_scope_files.update(sources)
                    logger.debug(f"Line {line_num}: {verb.upper()} instruction added {len(sources)} files from context")
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    logger.warning(f"Failed to parse {verb.upper()} instruction on line {line_num}: {e}")
                    logger.debug(f"Problematic line: {original_line}")

            if verb in ['from']:
                target = args_str.strip()
                target = target.split(' as ',1)[0].strip()
                target = target.split(' AS ',1)[0].strip()

                for supported_args in [
                    'IMAGE_PREFIX', 'OSS_FUZZ_BASE_BUILDER_IMAGE'
                ]:
                    m = '${' + supported_args + '}'
                    if m in target:
                        # Check to see if one was provided in the docker build args
                        if supported_args in args.build_args:
                            target = target.replace(m, args.build_args[supported_args])
                        else:
                            target = target.replace(m, '')

                if not target:
                    continue
                    
                target = target.split('/')[-1]
                parts = target.rsplit(':', 1)
                if len(parts) == 2:
                    dependent_images.append(parts)
                else:
                    dependent_images.append([parts[0], 'latest'])

        logger.info(f"Parsed dockerfile '{args.dockerfile.absolute()}' with context '{args.context.absolute()}'")
        for image_parts in dependent_images:
            image, tag = image_parts
            logger.info(f" 📦 Depends on {self._strip_image_name(image)}{f':{tag}' if tag else ''}")
        logger.info(f" 📄 Found {len(in_scope_files)} files in scope")

        return list(in_scope_files), dependent_images

    def _parse_add_copy_instruction(self, build_args, args_str: str, build_context: Path) -> List[Path]:
        """Parse ADD/COPY instruction arguments and return list of source files"""
        import shlex
        import glob
        
        # Handle JSON array format ["src1", "src2", "dest"]
        if args_str.strip().startswith('[') and args_str.strip().endswith(']'):
            try:
                import json
                args_list = json.loads(args_str)
            except json.JSONDecodeError:
                # Fallback to shell-like parsing
                args_list = shlex.split(args_str)
        else:
            # Parse shell-like arguments
            args_list = shlex.split(args_str)
        
        if len(args_list) < 2:
            return []
            
        # Create argument parser for ADD/COPY options
        argp = argparse.ArgumentParser()
        argp.add_argument('--keep-git-dir', action='store_true')
        argp.add_argument('--checksum')
        argp.add_argument('--chown')
        argp.add_argument('--chmod')
        argp.add_argument('--from', dest='from_image')
        argp.add_argument('--link', action='store_true')
        argp.add_argument('--exclude', action='append', default=[])
        argp.add_argument('sources', nargs='*')
        
        # Parse known and unknown arguments
        parsed_args, unknown_args = argp.parse_known_args(args_list)

        if parsed_args.from_image:
            # In this case we don't need to collect the files as they are part of the dependent image
            return []
        
        # All remaining arguments are sources except the last one (which is dest)
        all_sources = parsed_args.sources + unknown_args
        if len(all_sources) < 2:
            return []
            
        # Last argument is destination, everything else is source
        sources = all_sources[:-1]
        dest = all_sources[-1]
        
        collected_files = []
        
        for source_pattern in sources:
            # Skip URLs (ADD can use remote URLs)
            if source_pattern.startswith(('http://', 'https://', 'ftp://')):
                continue
                
            # Resolve source pattern relative to build context
            if source_pattern.startswith('/'):
                # Absolute paths are relative to build context
                source_pattern = source_pattern[1:]
                
            source_path = build_context / source_pattern
            
            # Handle wildcards
            if '*' in source_pattern or '?' in source_pattern:
                # Use glob to find matching files
                glob_pattern = str(build_context / source_pattern)
                matching_paths = glob.glob(glob_pattern, recursive=True)
                
                for match in matching_paths:
                    match_path = Path(match)
                    if match_path.is_file():
                        rel_path = match_path.relative_to(build_context)
                        collected_files.append(rel_path)
                    elif match_path.is_dir():
                        # Recursively add all files in directory
                        for file_path in match_path.rglob('*'):
                            if file_path.is_file():
                                rel_path = file_path.relative_to(build_context)
                                collected_files.append(rel_path)
            else:
                # Direct file/directory reference
                if source_path.exists():
                    if source_path.is_file():
                        rel_path = source_path.relative_to(build_context)
                        collected_files.append(rel_path)
                    elif source_path.is_dir():
                        # Recursively add all files in directory
                        for file_path in source_path.rglob('*'):
                            try:
                                if file_path.is_file():
                                    rel_path = file_path.relative_to(build_context)
                                    collected_files.append(rel_path)
                            except Exception as e:
                                logger.warning(f"Failed to add file {file_path}: {e}")
                else:
                    logger.warning(f"Source path does not exist: {source_path}")

        # exclude dockerignore files
        collected_files = [
            (build_context / rel_file_path).absolute()
            for rel_file_path in collected_files
            if not check_if_excluded_by_docker_ignore(rel_file_path, build_args.docker_ignore_rules)
        ]

        return collected_files

    def get_hash_for_build_command(self, build_command: List[str]) -> str:
        args = self.parse_docker_args(build_command)

        files_in_scope, dependent_images = self.parse_dockerfile(args)

        file_hash_list = []
        # Recursively walk the build directory and hash all files which are not ignored

        context_path = args.context
        context_path_absolute = context_path.absolute()

        for file_path in files_in_scope:
            try:
                file_path = file_path.absolute()
                # Get relative path from build context for dockerignore checking
                rel_file_path = file_path.relative_to(context_path_absolute)

                permission_bits = file_path.stat().st_mode & 0o777
                
                file_hash = hash_file_streaming(file_path, algorithm='sha1')
                file_hash_list.append((rel_file_path, file_hash, permission_bits))
            except Exception as e:
                logger.warning(f"Failed to hash file {file_path}: {e}")

        dependent_images.sort(key=lambda x: x[0])
        # TODO fetch the hashes for the dependent images
        depends_list = '\n'.join([
            f"{self._strip_image_name(image)}{f':{tag}' if tag and not self.get_hash_for_image(image) and tag != 'latest' and not 'sha256' in image else ''}: {self.get_hash_for_image(image)}"
            for image,tag in dependent_images
        ])

        # Sort the file hash list by file path
        file_hash_list.sort(key=lambda x: x[0])

        full_list = '\n'.join([
            f"{file_path} {file_hash} {oct(permission_bits)}"
            for file_path, file_hash, permission_bits in file_hash_list]
        )

        docker_file_hash = hash_file_streaming(args.dockerfile, algorithm='sha1')

        full_data = f'Dockerfile: {docker_file_hash}\n\n{depends_list}\n\n{full_list}'
        img_name=self._strip_image_name(args.tags[0]).replace("/","-")
        Path(f'/tmp/docker-cache-hash-data-{img_name}.txt').write_text(full_data)

        logger.info(str(args.dockerfile) + ' -- ' + str(full_data.split('\n\n')[:2]))


        final_hash = hashlib.sha1(full_data.encode()).hexdigest()

        logger.info(f" 🌵 Final hash: {final_hash}")

        return final_hash, dependent_images

    def _load_deployment_cache(self, lock=True) -> dict:
        local_image_cache = self.deployment_cache
        if lock:
            with FileLock(str(self.deployment_cache) + '.lock'):
                if not local_image_cache.exists():
                    return {}
            
                return json.loads(local_image_cache.read_text())
        
        if not local_image_cache.exists():
            return {}
        
        return json.loads(local_image_cache.read_text())

    def add_to_deployment_cache(self, image_name: str, hash: str):
        image_name = self._strip_image_name(image_name)
        local_image_cache = Path(self.deployment_cache)
        tmp_file = Path(str(self.deployment_cache) + '.tmp')
        with FileLock(str(self.deployment_cache) + '.lock'):
            local_image_cache_data = self._load_deployment_cache(lock=False)
            local_image_cache_data[image_name] = hash

            tmp_file.write_text(json.dumps(local_image_cache_data))
            tmp_file.rename(local_image_cache)

    def _load_local_daemon_cache(self, lock=True) -> dict:
        local_image_cache = self.local_daemon_cache
        if lock:
            with FileLock(str(self.local_daemon_cache) + '.lock'):
                if not local_image_cache.exists():
                    return {}
            
                return json.loads(local_image_cache.read_text())
        
        if not local_image_cache.exists():
            return {}
        
        return json.loads(local_image_cache.read_text())

    def add_to_local_daemon_cache(self, image_name: str, hash: str, cached_remote:str =None):
        logger.info(f"✔️ Adding {image_name}@{hash} to local daemon cache")
        full_image_name = image_name
        digest = self.get_local_image_digest(image_name)

        image_name = self._strip_image_name(image_name)
        local_image_cache = Path(self.local_daemon_cache)
        tmp_file = Path(str(self.local_daemon_cache) + '.tmp')
        with optional_filelock(str(self.local_daemon_cache) + '.lock') as got_lock:
            if not got_lock:
                logger.warning(f"🤡 Couldn't acquire lock for {self.local_daemon_cache}, proceeding anyway")

            local_image_cache_data = self._load_local_daemon_cache(lock=False)
            if not image_name in local_image_cache_data:
                local_image_cache_data[image_name] = {}
            local_image_cache_data[image_name][hash] = dict(
                hash=hash,
                digest=digest,
                full_image_name=full_image_name,
                cached_remote=cached_remote,
            )

            tmp_file.write_text(json.dumps(local_image_cache_data))
            tmp_file.rename(local_image_cache)

    def _strip_image_name(self, image_name: str) -> str:
        parts = image_name.split('/',1)
        # Remove the registry name
        if '.' in parts[0]:
            image_name = parts[-1]
        elif len(parts) > 1 and ':' in parts[0]:
            # Handle registries like localhost:5000
            image_name = parts[-1]

        image_name = image_name.replace('shellphish-support-syndicate/','')
        
        # Remove the tag as we don't care about it for this lookup
        image_name = image_name.split(':',1)[0]

        return image_name

    def get_hash_for_image(self, image: str) -> str:
        # Check to see if we built the image using our cache method

        image_name = self._strip_image_name(image)

        local_image_cache_data = self._load_deployment_cache()
        
        if image_name not in local_image_cache_data:
            return None
        
        return local_image_cache_data[image_name]


    def _run_docker_command(self, command: List[str], check=True, capture_output=False, unbuffer=False):
        logger.info(f"+ docker {' '.join(command)}")
        base = [DOCKER_BINARY]
        if unbuffer:
            base = ['unbuffer', DOCKER_BINARY]
        if capture_output:
            return subprocess.check_output(base + command)
        else:
            subprocess.run(base + command, check=check)

    def docker_tag(self, image_name: str, tag: str):
        self._run_docker_command(['tag', image_name, tag])

    def docker_pull(self, image_name: str):
        self._run_docker_command(['pull', image_name ], unbuffer=True)

    def docker_push(self, image_name: str):
        self._run_docker_command(['push', image_name])

    def get_local_image_digest(self, image_name: str) -> str:
        return self._run_docker_command(['inspect', '--format', '{{.Id}}', image_name], check=False, capture_output=True).decode('utf-8').strip()

    def import_image(self, digest: str, tag: str):
        target_registry, image = tag.split('/',1)

        cmd = [
            'az', 'acr', 'import',
            '--name', target_registry,
            '--source', digest,
            '--image', image,
            '--force',
        ]
        if os.environ.get('AZ_RESOURCE_GROUP'):
            cmd += ['-g', os.environ['AZ_RESOURCE_GROUP']]

        logger.info(f"+ {' '.join(cmd)}")
        
        # Start the process
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        try:
            # Wait for 20 seconds to see if the command fails early
            stdout, stderr = process.communicate(timeout=10)
            # If we get here, the command completed within 20 seconds
            if process.returncode != 0:
                logger.error(f"⚠️ az acr import failed: {stderr.decode()}")
                raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)
        except subprocess.TimeoutExpired:
            # Command is still running after 20 seconds, assume it's working fine
            logger.info("az acr import is running successfully, moving to background")
            #process.terminate()
            #try:
            #    # Give it a moment to terminate gracefully
            #    process.wait(timeout=5)
            #except subprocess.TimeoutExpired:
            #    # Force kill if it doesn't terminate gracefully
            #    process.kill()
            #    #process.wait()

    def az_check_if_cache_digest_exists(self, digest_image: str):
        #artiphishell.azurecr.io/oss-fuzz-instrumentation-prebuild-griller@sha256:de90f2eb4be310a9c2b12e8d8e2c3e9fc944b9fd37f40730efa0c27422914dc0
        '''
        az acr repository show --name artiphishell --image oss-fuzz-instrumentation-prebuild-griller@sha256:de90f2eb4be310a9c2b12e8d8e2c3e9fc944b9fd37f40730efa0c27422914dc0
{
  "architecture": "amd64",
  "changeableAttributes": {
    "deleteEnabled": true,
    "listEnabled": true,
    "readEnabled": true,
    "writeEnabled": true
  },
  "configMediaType": "application/vnd.docker.container.image.v1+json",
  "createdTime": "2025-05-25T05:48:51.9318337Z",
  "digest": "sha256:de90f2eb4be310a9c2b12e8d8e2c3e9fc944b9fd37f40730efa0c27422914dc0",
  "imageSize": 1897455860,
  "lastUpdateTime": "2025-05-25T05:48:51.9318337Z",
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "os": "linux",
  "tags": [
    "cache-featfast-ci-build"
  ]
  '''
        target_registry, image = digest_image.split('/',1)
        if not 'azurecr' in target_registry:
            logger.warning(f"🚫☁️ {digest_image} is not an Azure Container Registry image, skipping verification")
            return True

        cmd = [
            'az', 'acr', 'repository', 'show',
            '--name', target_registry,
            '--image', image,
            '-g', 'ARTIPHISHELL-CI-TINY',
        ]

        try:
            res = subprocess.check_output(cmd)
            res = json.loads(res)
        except Exception as e:
            logger.warning(f"🚫☁️ {digest_image} is not in the Azure Container Registry, will need to be rebuilt")
            return False
        
        return True


    def get_remote_image_digest(self, image_name: str) -> str:
        data = self._run_docker_command(['inspect', '--format', 'json', image_name], check=False, capture_output=True).decode('utf-8').strip()
        data = json.loads(data)
        repo_digest = data[0]['RepoDigests']
        if len(repo_digest) == 0:
            return None
        if len(repo_digest) == 1:
            return repo_digest[0]
        for digest in repo_digest:
            if digest.startswith(self.cache_registry):
                return digest
        return None

        


    # We have 3 cache directories
    # 1. Deployment Cache: For this specific build set we have calculated hashes
    # 2. Local Image Cache: When we build an image locally with a given hash, we save the image digest
    # 3. Registry Cache: When we build an image we can push it to the cache registry, we need to update the remote directory to say the hash has a specific remote digest in the registry

    def tag_if_in_local_daemon_cache(self, tags: List[str], local_hash: str):
        local_daemon_cache_data = self._load_local_daemon_cache()
        found_in_local_daemon_cache = None
        for tag in tags:
            tag = self._strip_image_name(tag)
            all_entries = local_daemon_cache_data.get(tag)
            if not all_entries:
                continue
            cache_entry = all_entries.get(local_hash)
            if not cache_entry:
                continue
            # Check if the hash matches the hash in the local daemon cache
            assert cache_entry['hash'] == local_hash
            found_in_local_daemon_cache = cache_entry
            break
        
        if found_in_local_daemon_cache:
            logger.info(f"✅ Image {found_in_local_daemon_cache['full_image_name']}@{local_hash} found in local daemon cache")
            # Tag this image as all of the target tags
            full_image_name = found_in_local_daemon_cache['full_image_name']
            digest = found_in_local_daemon_cache['digest']
            try:
                for tag in tags:
                    self.docker_tag(digest, tag)
            except:
                return None

            digest = self.get_local_image_digest(tags[0])
            if digest != found_in_local_daemon_cache['digest']:
                logger.warning(f"Digest mismatch for {full_image_name}: {digest} != {found_in_local_daemon_cache['digest']}")

            for tag in tags:
                self.add_to_local_daemon_cache(tag, local_hash, cached_remote=found_in_local_daemon_cache['cached_remote'])

        return found_in_local_daemon_cache

    def find_image_in_remote_registry(self, image_name: str, local_hash: str) -> str:
        image_name = self._strip_image_name(image_name)
        # Check the remote registry directory.
        # If it matches then we pull that remote image and tag it for our local image
        url = f"{WORKER_API_URL}/lookup?image_name={image_name}&cache_key={local_hash}"
        response = requests.get(url)
        if response.status_code != 200:
            logger.warning(f"🚫🌐 Failed to check remote registry for {image_name}: {response.status_code}")
            return None
        response_json = response.json()
        logger.debug(f"🌐🌐🌐 {response_json}")
        if not response_json or not response_json.get('found'):
            return None
        return response_json

    def save_remote_cache_entry(self, remote_image_name: str, local_hash: str, remote_digest: str):
        if WORKER_TOKEN is None:
            logger.warning("🚫🌐 WORKER_TOKEN is not set, skipping remote cache entry save")
            return False
        
        assert remote_image_name.startswith(self.cache_registry)
        url = f"{WORKER_API_URL}/store?token={WORKER_TOKEN}&image_name={remote_image_name}&cache_key={local_hash}&image_digest={remote_digest}"
        response = requests.post(url)
        if response.status_code != 200:
            logger.warning(f"🚫🌐 Failed to save remote cache entry for {remote_image_name}: {response.status_code}")
            return False
        logger.debug(f"🌐🌐🌐 {response.text}")
        return True

    def ensure_cached_image_locally(self, image, local_hash):
        logger.info(f"🔍 Ensuring {image}@{local_hash} is locally cached")

        # This tries to ensure we end up with the cached image locally so we can use it

        # First we check if this hash matches the local image directory
        # if it does, then we need to check that the image is still at that tag
        found_in_local_daemon_cache = self.tag_if_in_local_daemon_cache([image], local_hash)

        if found_in_local_daemon_cache:
            return True

        logger.info(f"👻 Image {image}@{local_hash} not found in local daemon cache")

        found_in_remote_registry = self.find_image_in_remote_registry(image, local_hash)
        if not found_in_remote_registry:
            logger.warning(f"⚠️ Unable to get image {image}@{local_hash} for local use")
            exit(-1)

        remote_cache_image = found_in_remote_registry['full_image_name']

        try:
            self.docker_pull(remote_cache_image)
        except Exception as e:
            logger.warning(f"⚠️ Unable to pull image {remote_cache_image}: {e}")
            exit(-1)

        self.docker_tag(remote_cache_image, image)
        logger.info(f"📥 Pulled {remote_cache_image} and tagged it as {image}")

        found_in_local_daemon_cache = self.tag_if_in_local_daemon_cache([image], local_hash)

        return True

    def build_image(self, build_command: List[str], docker_args: dict, local_hash: str, dependent_images: List[str]):
        logger.info(f"🔨 Building {docker_args.tags[0]}@{local_hash}")

        if self.push_mode:
            # Remove '--push' from the build command
            build_command = [cmd for cmd in build_command if cmd != '--push']

        for dep_image,tag in dependent_images:
            dep_image_hash = self.get_hash_for_image(dep_image)
            if not dep_image_hash:
                # TODO surpress this warning if this is a remote image in a regsitry
                logger.warning(f"Unable to get hash for dependent image {dep_image}, skipping...")
                continue

            self.ensure_cached_image_locally(dep_image, dep_image_hash)


        # TODO we need to get the dependant images if we have not gotten them already...
        self._run_docker_command(['build'] + build_command)

        self.add_to_local_daemon_cache(docker_args.tags[0], local_hash, cached_remote=None)

        return docker_args.tags[0]

    def handle_build_command(self, build_command: List[str]):
        docker_args = self.parse_docker_args(build_command)
        if docker_args.push:
            self.push_mode = True
        if docker_args.quiet:
            logger.setLevel(logging.WARNING)

        local_hash, dependent_images = self.get_hash_for_build_command(build_command)

        if docker_args.dry_run:
            exit(0)

        # save the hash to the local cache
        for tag in docker_args.tags:
            self.add_to_deployment_cache(tag, local_hash)

        # Once we have calculated our cache hash for this given image, we need to decide what to do

        need_to_build = True

        # First we check if this hash matches the local image directory
        # if it does, then we need to check that the image is still at that tag
        found_in_local_daemon_cache = self.tag_if_in_local_daemon_cache(docker_args.tags, local_hash)

        should_check_remote_cache = True

        if found_in_local_daemon_cache:
            need_to_build = False
            remote_digest = found_in_local_daemon_cache.get('cached_remote')
            if remote_digest and type(remote_digest) is str and remote_digest.startswith(self.cache_registry):
                should_check_remote_cache = False
        else:
            logger.info(f"👻 Image {docker_args.tags[0]}@{local_hash} not found in local daemon cache")

        found_in_remote_registry = None

        # If not then we check the remote registry directory.
        # If it matches then we pull that remote image and tag it for our local image
        if need_to_build or self.import_mode or (self.push_cache and should_check_remote_cache):
            found_in_remote_registry = self.find_image_in_remote_registry(docker_args.tags[0], local_hash)

            if found_in_remote_registry:
                image_digest = found_in_remote_registry['image_digest']
                # Check if it was found in the target cache registry
                if not image_digest.startswith(self.cache_registry):
                    logger.warning(f"🚫🌐 Image {docker_args.tags[0]}@{local_hash} found in remote registry but not in target cache registry")
                    found_in_remote_registry = None

            if found_in_remote_registry:
                image_digest = found_in_remote_registry['image_digest']

                if self.import_mode and not self.must_download:
                    # We don't need to download if we are doing az import
                    if not self.az_check_if_cache_digest_exists(image_digest):
                        found_in_remote_registry = None
                elif self.only_check_mode and not self.must_download:
                    # We don't need to download if we are only checking that our build works and we already have a cache hit
                    pass
                elif need_to_build:
                    try:
                        self.docker_pull(image_digest)
                    except Exception as e:
                        logger.warn('⚠️ Unable to pull image from remote registry, the cache was likely deleted')
                        found_in_remote_registry = None
                    else:
                        self.docker_tag(image_digest, docker_args.tags[0])
                        self.add_to_local_daemon_cache(docker_args.tags[0], local_hash, cached_remote=image_digest)
                if found_in_remote_registry:
                    need_to_build = False
            else:
                logger.info(f"👻 Image {docker_args.tags[0]}@{local_hash} not found in remote registry")

        target_image_name = docker_args.tags[0]
        if need_to_build:
            target_image_name = self.build_image(build_command, docker_args, local_hash, dependent_images)

        if (
            self.push_cache and not found_in_remote_registry
            and should_check_remote_cache
        ):
            image_name = self._strip_image_name(target_image_name)
            cache_image_name = f"{self.cache_registry}/{image_name}:cache"
            if self.git_branch:
                cache_image_name += f"-{self.git_branch}"[:15]
            self.docker_tag(docker_args.tags[0], cache_image_name)
            try:
                self.docker_push(cache_image_name)
            except Exception as e:
                logger.warning(f"⚠️ Unable to push image {cache_image_name}: {e}")
                if self.import_mode:
                    logger.warning(f"⚠️ Unable to push image {cache_image_name} to remote registry, this is required for import mode")
                    exit(-1)
            else:
                found_in_remote_registry = dict(
                    full_image_name=cache_image_name,
                    image_digest=self.get_remote_image_digest(cache_image_name),
                    found=True,
                )
                digest = self.get_remote_image_digest(cache_image_name)
                if not digest:
                    logger.warning(f"⚠️ Unable to get digest for {cache_image_name}")
                else:
                    if self.save_remote_cache_entry(cache_image_name, local_hash, digest):
                        self.add_to_local_daemon_cache(target_image_name, local_hash, cached_remote=digest)

        if self.push_mode:
            if self.import_mode and found_in_remote_registry:
                # Rather than pushign a local copy we will use the az import command to directly copy the remote cached version
                digest = found_in_remote_registry['image_digest']
                logger.warning(f"⚡ Importing {digest} to {docker_args.tags[0]}")
                for tag in docker_args.tags:
                    self.import_image(digest, tag)
            else:
                for tag in docker_args.tags:
                    try:
                        self.docker_push(tag)
                    except Exception as e:
                        logger.warning(f"⚠️ Unable to push image {tag}: {e}")
                        os.exit(-1)

        

def build_docker_compose_service(args, name: str, cfg: dict):
    rel_dir = args.file.parent
    cmd = [
        __file__,
        'build',
    ]
    if cfg.get('image'):
        cmd += ['-t', cfg['image']]
    else:
        cmd += ['-t', f'{name}:latest']

    bld = cfg.get('build')
    context = rel_dir
    if bld:
        if bld.get('args'):
            for k, v in bld['args'].items():
                cmd += ['--build-arg', f'{k}={v}']
        if bld.get('context'):
            context = rel_dir / bld['context']
            context = context.absolute()
        if bld.get('dockerfile'):
            dockerfile = context / bld['dockerfile']
            cmd += ['-f', str(dockerfile.absolute())]

    cmd += [str(context.absolute())]

    if args.quiet:
        cmd += ['-q']

    if args.push:
        cmd += ['--push']

    logger.info(f"📦 Checking {name} with command {cmd}")

    return subprocess.Popen(cmd)





def handle_docker_compose(docker_compose_args: List[str]):
    import argparse
    
    # Create argument parser for docker compose
    argp = argparse.ArgumentParser(description='Docker compose wrapper with cache support')
    
    # Add docker compose specific arguments
    argp.add_argument('--profile', dest='profile', action='append',
                     help='Specify a profile to enable')
    
    argp.add_argument('-f', '--file', dest='file', 
                     help='Specify an alternate compose file')
    
    argp.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                     help='Pull without printing progress information')
    
    argp.add_argument('--push', dest='push', action='store_true',
                     help='Push the images to the registry')
    
    # The subcommand (like 'build', 'up', etc.) - single argument
    argp.add_argument('subcommand',
                     help='Docker compose subcommand')
    
    # Parse known args, rest go to other_args
    args, other_args = argp.parse_known_args(docker_compose_args)

    if args.quiet:
        logger.setLevel(logging.WARNING)

    if not args.file:
        if Path('docker-compose.yaml').exists():
            args.file = 'docker-compose.yaml'
        elif Path('docker-compose.yml').exists():
            args.file = 'docker-compose.yml'
        elif Path('dockercompose.yaml').exists():
            args.file = 'dockercompose.yaml'
        elif Path('dockercompose.yml').exists():
            args.file = 'dockercompose.yml'
        else:
            raise Exception("No docker compose file found")
    args.file = Path(args.file).absolute()

    if args.subcommand == 'push':
        args.push = True
        args.subcommand = 'build'

    if args.subcommand != 'build':
        # Pass through to docker compose
        subprocess.run([DOCKER_BINARY, 'compose'] + docker_compose_args)
        return

    config = yaml.safe_load(open(args.file))
    logger.debug(f"🔍 Loading docker compose config from {args.file}")
    logger.debug(f"🔍 {config}")

    active_services = config['services']
    if args.profile:
        active_services = {
            name: s
            for name, s in active_services.items()
            if not s.get('profiles')
               or any(p in args.profile for p in s['profiles'])
        }
    else:
        active_services = {
            name: s
            for name, s in active_services.items()
            if not s.get('profiles')
        }

    sub_procs = {}

    use_parallel = os.environ.get('USE_PARALLEL_DOCKER_COMPOSE', 'false') == 'true'

    MAX_PARALLEL_BUILD_JOBS = 16

    for service_name, service_config in active_services.items():
        p = build_docker_compose_service(args, service_name, service_config)
        if use_parallel:
            sub_procs[service_name] = p

            while len(sub_procs) >= MAX_PARALLEL_BUILD_JOBS:
                # Iterate over the sub_proces polling each to see if any have finished
                for service_name, p in sub_procs.copy().items():
                    try:
                        if p.poll() is not None:
                            del sub_procs[service_name]
                            if p.returncode != 0:
                                logger.error(f"🚫 Build failed for service {service_name}")
                                exit(1)
                    except Exception as e:
                        pass
                if len(sub_procs) < MAX_PARALLEL_BUILD_JOBS:
                    break
                time.sleep(1)
        else:
            p.wait()
            if p.returncode != 0:
                logger.error(f"🚫 Build failed for service {service_name}")
                exit(1)

    for service_name, p in sub_procs.items():
        p.wait()
        if p.returncode != 0:
            logger.error(f"🚫 Build failed for service {service_name}")
            exit(1)

    
    # TODO: Implement docker compose handling logic
    pass

def main():
    import sys
    if sys.argv[1] == 'reset-build-cache':
        Path(f'/tmp/docker-cache-for-deployment.json').unlink(missing_ok=True)
        logger.info("🧹 Reset build cache")
        return

    if sys.argv[1] == 'build':
        docker_cache = DockerCache(
            cache_registry=os.environ.get('DOCKER_CACHE_REGISTRY', "artiphishelltiny.azurecr.io"),
            import_mode=os.environ.get('DOCKER_IMPORT_MODE', 'false') == 'true',
            push_mode=False,
            push_cache=os.environ.get('PUSH_DOCKER_CACHE', 'false') == 'true',
            git_branch=os.environ.get('GIT_BRANCH'),
            only_check_mode=os.environ.get('DOCKER_ONLY_CHECK', 'false') == 'true',
            must_download=os.environ.get('DOCKER_CACHE_MUST_DOWNLOAD', 'false') == 'true'
        )

        docker_cache.handle_build_command(sys.argv[2:])
    elif sys.argv[1] == 'compose':
        handle_docker_compose(sys.argv[2:])
    else:
        # Pass through to docker
        subprocess.run([DOCKER_BINARY] + sys.argv[1:])

# TODO handle the case when the remote cache digest image is deleted

if __name__ == "__main__":
    main()


