

import contextlib
import hashlib
import logging
import os
from pathlib import Path
from queue import Queue
import shutil
import subprocess
import tempfile
from typing import Dict, Optional, Union
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
import yaml
from shellphish_crs_utils.filesystem import DirectoryMonitor
from shellphish_crs_utils import filesystem as fs

log = logging.getLogger(__name__)

class PDTRepo:
    def __init__(self, main_dir, lock_dir, uploaded_dir=None, cokeyed_dirs=None, download_file=None):
        cokeyed_dirs = cokeyed_dirs or {}
        self.main_dir = Path(main_dir)
        self.lock_dir = Path(lock_dir)
        self.uploaded_dir = Path(uploaded_dir) if uploaded_dir else None
        self.cokeyed_repo_dirs = cokeyed_dirs
        self.download_file = download_file
        assert os.path.exists(main_dir), f"Data directory {main_dir} does not exist"
        assert os.path.exists(lock_dir), f"Lock directory {lock_dir} does not exist"
        if uploaded_dir:
            assert os.path.exists(uploaded_dir), f"Uploaded directory {uploaded_dir} does not exist"
        for cokeyed_name, cokeyed_dir in cokeyed_dirs.items():
            assert os.path.exists(cokeyed_dir), f"Cokeyed directory for {cokeyed_name} => {cokeyed_dir} does not exist"

        self.cokeyed_repo_dirs = {k: Path(v) for k, v in cokeyed_dirs.items()}

    def __repr__(self) -> str:
        return f"PDTRepo(main_dir={self.main_dir}, lock_dir={self.lock_dir}, uploaded_dir={self.uploaded_dir}, cokeyed_dirs={self.cokeyed_repo_dirs}, download_file={self.download_file})"

    def __str__(self) -> str:
        return repr(self)
    
    @contextlib.contextmanager
    def lock(self, filename):
        with open(self.lock_dir / filename, "w") as f:
            f.write("")
            f.flush()
        try:
            yield
        finally:
            os.remove(self.lock_dir / filename)

    def locked_keys(self):
        return [f.name for f in self.lock_dir.iterdir()]
    
    def ready_keys(self):
        # we must FIRST retrieve all keys to avoid race conditions
        all_keys = [f.name for f in self.main_dir.iterdir()]
        locked_keys = set(self.locked_keys())
        return [key for key in all_keys if key not in locked_keys]

    def get_content_paths(self, filename):
        if not self.has_unlocked(filename):
            raise ValueError(f"Key {filename} is not unlocked")

        paths = {}
        paths['main_repo'] = self.main_dir / filename
        if self.uploaded_dir:
            paths['uploaded_repo'] = self.uploaded_dir / filename
        paths['cokeyed'] = {}
        for cokeyed_name, cokeyed_dir in self.cokeyed_repo_dirs.items():
            paths['cokeyed'][cokeyed_name] = cokeyed_dir / filename
        return paths

    def is_locked(self, filename):
        return os.path.exists(self.lock_dir / filename)

    def was_uploaded(self, filename):
        assert self.uploaded_dir, f"Repo {self} does not have an uploaded_dir"
        return os.path.exists(self.uploaded_dir / filename)

    def get_upload_result(self, filename):
        if not self.uploaded_dir:
            raise ValueError(f"Upload results are not available for repos without an uploaded_dir! (repo: {self})")
        try:
            with open(self.uploaded_dir / filename, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return None

    def has(self, filename):
        return os.path.exists(self.main_dir / filename)
    
    def has_unlocked(self, filename):
        return self.has(filename) and not self.is_locked(filename)
    
    def has_locked(self, filename):
        return self.has(filename) and self.is_locked(filename)
    
    def _store(self, dir: Path, filename: str, content: Union[str, bytes, memoryview, Path]):
        assert self.is_locked(filename), f"Key {filename} is not locked"
        if isinstance(content, Path):
            subprocess.check_call(["cp", "-r", str(content), str(dir / filename)])
        else:
            with open(dir / filename, "wb") as f:
                f.write(content.encode('utf-8') if type(content) == str else content)

    def upload(self, filename: str, content: Union[str, bytes, memoryview, Path],
                **cokeyed: Dict[str, Union[str, bytes, memoryview, Path]]):
        if self.has(filename):
            raise ValueError(f"Key {filename} already exists")
        with self.lock(filename):
            self._store(self.main_dir, filename, content)
            assert cokeyed.keys() == self.cokeyed_repo_dirs.keys(), f"Expected cokeyed keys {self.cokeyed_repo_dirs.keys()} but got {cokeyed.keys()}"
            for cokeyed_name, cokeyed_content in cokeyed.items():
                self._store(self.cokeyed_repo_dirs[cokeyed_name], filename, cokeyed_content)

    def upload_dedup(self, content: Union[str, bytes, memoryview, Path],
                      **cokeyed: Dict[str, Union[str, bytes, memoryview, Path]]):
        if isinstance(content, Path):
            with open(content, "rb") as f:
                sha = hashlib.md5(f.read()).hexdigest()
        else:
            sha = hashlib.md5(content.encode('utf-8') if type(content) == str else content).hexdigest()
        self.upload(sha, content, **cokeyed)
        return sha

class PDTRepoMonitor(DirectoryMonitor):
    def __init__(self, repo: PDTRepo, new_repo_entries_queue: Queue, **kwargs):
        self.repo = repo
        super().__init__(
            new_repo_entries_queue,
            self.repo.main_dir,
            self.repo.lock_dir,
            *[cokeyed_dir for name, cokeyed_dir in self.repo.cokeyed_repo_dirs], **kwargs
        )

    def __get_repo_relative_location(self, path):
        if path.is_relative_to(self.repo.main_dir):
            return 'main_repo', path.relative_to(self.repo.main_dir)
        elif path.is_relative_to(self.repo.lock_dir):
            return 'lock_repo', path.relative_to(self.repo.lock_dir)
        elif self.repo.uploaded_dir and path.is_relative_to(self.repo.uploaded_dir):
            return 'uploaded_repo', path.relative_to(self.repo.uploaded_dir)
        else:
            for name, cokeyed_dir in self.repo.cokeyed_repo_dirs.items():
                if path.is_relative_to(cokeyed_dir):
                    return ('cokeyed_repo', name), path.relative_to(cokeyed_dir)
        raise ValueError(f"Path {path} is not in any of the repo directories")
    
    def get_repo_location(self, path):
        try:
            location, relative_path = self.__get_repo_relative_location(path)
            key, *rest = str(relative_path).split('/')
            log.debug(f"get_repo_location: resolved {path=} to {location=}, {key=}, {rest=}")
            return location, key, '/'.join(rest)
        except ValueError:
            log.error(f"get_repo_location: {path=} is not in any of the repo directories")
            if artiphishell_should_fail_on_error():
                assert False
            return None
    
    def event_is_interesting(self, event):
        if event.event_type != fs.EVENT_TYPE_DELETED:
            log.debug(f"event_is_interesting: False, {event=}: {event.event_type=}, {event.src_path=}")
            return False
        if Path(event.src_path).is_dir():
            log.debug(f"event_is_interesting: False, {event=}: {event.src_path=} is a directory")
            return False
        if (repo_location := self.get_repo_location(Path(event.src_path))) is None:
            log.debug(f"event_is_interesting: False, {event=}: {event.src_path=} is not in any repo directory")
            return False
        repo_kind, key, relative_path = repo_location
        log.debug(f"event_is_interesting: {repo_kind == 'lock_repo'}, {event=}: {repo_kind=}, {key=}, {relative_path=}")
        return repo_kind == 'lock_repo'

    def event_is_ready(self, event):
        return True

    def compute_output(self, event):
        if (repo_location := self.get_repo_location(Path(event.src_path))) is None:
            return None
        log.debug(f"compute_output: {event=}: {repo_location=}")
        repo_kind, key, relative_path = repo_location
        return key
    
    def external_update(self, force_push_pending=False):
        log.debug(f"external_update: {force_push_pending=}")
        return super().external_update(force_push_pending)

    @property
    def new_repo_entries_queue(self):
        return self.queue


# def make_test_repo():
#     tmp = Path(tempfile.mkdtemp())
#     main_dir = (tmp / "data")
#     main_dir.mkdir()
#     lock_dir = (tmp / "lock")
#     lock_dir.mkdir()
#     uploaded_dir = (tmp / "uploaded")
#     uploaded_dir.mkdir()
#     meta = (tmp / "meta")
#     meta.mkdir()
#     fuk_dir = (tmp / "fuk")
#     fuk_dir.mkdir()

#     repo = PDTRepo(main_dir, lock_dir, uploaded_dir, fuk=fuk_dir, meta=meta)
#     return repo
