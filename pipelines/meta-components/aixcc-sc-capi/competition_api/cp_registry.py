import os
import pathlib
import shutil
import tempfile
from copy import deepcopy
from threading import RLock
from typing import Any

import git
from ruamel.yaml import YAML as RuamelYaml
from structlog.stdlib import get_logger
from vyper import v

YAML = RuamelYaml(typ="safe")
LOGGER = get_logger(__name__)


class SourceCommitMap:
    def __init__(self, workdir: pathlib.Path, source: str):
        repo = git.Repo(workdir / "src" / source)

        self.commit_hashes: set[str] = set()
        self.commits: set[git.Commit] = set()

        self.initial_commit: str | None = None

        for commit in repo.iter_commits():
            self.commit_hashes.add(commit.hexsha.lower())
            self.commits.add(commit)

            if not commit.parents:
                if self.initial_commit is not None:
                    raise ValueError(
                        f"Found another parentless commit in source {source} for CP in {workdir}:"
                        f" had {self.initial_commit}, found {commit.hexsha.lower()}"
                    )
                self.initial_commit = commit.hexsha.lower()

        if self.initial_commit is None:
            raise ValueError(
                f"Source {source} for CP in {workdir} does not have a commit with no parents"
            )

    def has(self, commit_sha: str):
        return commit_sha.lower() in self.commit_hashes


class CP:
    def __init__(self, name: str, root_dir: pathlib.Path, project_yaml: dict[str, Any]):
        self.name = name
        self.root_dir = root_dir
        self._project_yaml = project_yaml

        self.sources = self._project_yaml.get("cp_sources", {})
        self.source_commits: dict[str, SourceCommitMap] = {}

        self.commits = {
            source: SourceCommitMap(self.root_dir, source)
            for source in self.sources.keys()
        }

    def copy(self) -> pathlib.Path:
        workdir = tempfile.mkdtemp(dir=v.get("tempdir"))
        shutil.copytree(self.root_dir, workdir, dirs_exist_ok=True)
        return pathlib.Path(workdir)

    def is_initial_commit(self, ref: str) -> bool:
        return any(
            ref.lower() == commit_map.initial_commit
            for commit_map in self.commits.values()
        )

    def source_from_ref(self, ref: str) -> str | None:
        for source, commit_map in self.commits.items():
            if commit_map.has(ref):
                return source

        # Ref not found in any of the sources
        return None

    def head_ref_from_ref(self, ref: str) -> str | None:
        source = self.source_from_ref(ref)
        if source is None:
            return None
        return self.sources[source].get("ref", "main")

    def has(self, ref: str) -> bool:
        return self.source_from_ref(ref) is not None

    @property
    def project_yaml(self) -> dict[str, Any]:
        return deepcopy(self._project_yaml)


class CPRegistry:
    _instance = None
    _lock = RLock()

    def __init__(self):
        self._registry: dict[str, CP] = {}

        if self._registry:
            return

        self._load_from_disk()

    def _load_from_disk(self):
        with CPRegistry._lock:
            cp_root = v.get("cp_root")

            if not cp_root:
                LOGGER.warning(
                    "Bailing on initializing CPRegistry because cp_root was None"
                )
                return

            for item in os.listdir(cp_root):
                item = pathlib.Path(cp_root) / item
                if os.path.isdir(item) and os.path.isfile(item / "project.yaml"):
                    project_yaml = YAML.load(item / "project.yaml")
                    if not (name := project_yaml.get("cp_name")):
                        LOGGER.warning(
                            "project.yaml in %s missing cp_name key. Skipping it.", item
                        )
                        continue
                    cp = CP(name, item, project_yaml)
                    if not cp.sources:
                        LOGGER.warning(
                            "project.yaml in %s has no sources.  Skipping it.", item
                        )
                        continue
                    self._registry[name] = cp

                    has_internal = os.path.isdir(item / ".internal_only")
                    LOGGER.info(
                        "Loaded cp %s%s",
                        name,
                        " with internal folder" if has_internal else "",
                    )
                else:
                    LOGGER.info(
                        "Item %s in %s does not look like a challenge problem",
                        item,
                        v.get("cp_root"),
                    )

    def get(self, cp_name) -> CP | None:
        return self._registry.get(cp_name)

    def has(self, cp_name) -> bool:
        return cp_name in self._registry

    @classmethod
    def instance(cls):
        if not cls._instance:
            with cls._lock:
                cls._instance = CPRegistry()
        return cls._instance
