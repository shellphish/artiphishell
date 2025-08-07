"""This module is a sister to declarative, housing the functions needed to handle pipeline.yaml files.

Pipeline.yaml is a specification which lets you set up a pipeline or a piece thereof declaratively. Pipeline files can
specify all their dependencies, or they can specify only the classes of the missing dependencies, in which case before
they can be used they need to either be imported by another pipeline file or "locked", a process which automatically
allocates the needed resources and generates a lockfile, which is itself a pipeline file that imports the original
pipeline file.
"""

from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    ForwardRef,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    get_args,
    get_origin,
)
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from pathlib import Path
import os
import random
import subprocess

import yaml

from pydatatask.declarative import (
    build_ephemeral_picker,
    build_executor_picker,
    build_repository_picker,
    build_task_picker,
    host_constructor,
    quota_constructor,
)
from pydatatask.executor import Executor
from pydatatask.pipeline import Pipeline
from pydatatask.query.repository import QueryRepository
from pydatatask.quota import Quota
from pydatatask.repository import Repository
from pydatatask.session import Ephemeral, Session
from pydatatask.utils import safe_load

if TYPE_CHECKING:
    from dataclasses import dataclass as _dataclass_serial  # pylint: disable=reimported
else:

    def _reprocess(value, ty):
        if isinstance(ty, ForwardRef):
            try:
                ty = ty._evaluate(globals(), locals(), set())
            except TypeError:
                ty = ty._evaluate(globals(), locals())
        if is_dataclass(ty) and isinstance(value, dict):
            return ty(**value)
        elif get_origin(ty) is dict and isinstance(value, dict):
            for k, v in value.items():
                value[k] = _reprocess(v, get_args(ty)[1])
        elif get_origin(ty) is list and isinstance(value, list):
            for i, v in enumerate(value):
                value[i] = _reprocess(v, get_args(ty)[1])
        return value

    def _dataclass_serial(cls):
        def __post_init__(self):
            for myfield in myfields:
                setattr(self, myfield.name, _reprocess(getattr(self, myfield.name), myfield.type))

        cls.__post_init__ = __post_init__
        dcls = dataclass(cls)
        myfields = fields(dcls)
        return dcls


# pylint: disable=missing-class-docstring,missing-function-docstring
@_dataclass_serial
class Dispatcher:
    cls: str
    args: Dict[str, Any] = field(default_factory=dict)


@_dataclass_serial
class PriorityEntry:
    priority: int
    task: Optional[str] = None
    job: Optional[str] = None


@_dataclass_serial
class LinkSpec:
    repo: str
    kind: str
    key: Optional[str] = None
    jq_filter: Optional[str] = None
    cokeyed: Dict[str, str] = field(default_factory=dict)
    auto_meta: Optional[str] = None
    auto_values: Optional[Any] = None
    required_for_start: Optional[bool] = None
    required_for_success: Optional[bool] = None
    inhibits_start: Optional[bool] = None
    inhibits_output: Optional[bool] = None
    is_input: Optional[bool] = None
    is_output: Optional[bool] = None
    is_status: Optional[bool] = None
    force_path: Optional[str] = None
    DANGEROUS_filename_is_key: Optional[bool] = None
    content_keyed_md5: Optional[bool] = None
    equals: Optional[str] = None


@_dataclass_serial
class QuerySpec:
    result_type: str
    query: str
    parameters: Dict[str, str] = field(default_factory=dict)
    getters: Dict[str, str] = field(default_factory=dict)
    jq: Dict[str, str] = field(default_factory=dict)


@_dataclass_serial
class TaskSpec:
    executable: Dispatcher
    done: Optional[str] = None
    annotations: Dict[str, Any] = field(default_factory=dict)
    executor: Optional[str] = None
    ready: Optional[str] = None
    links: Dict[str, LinkSpec] = field(default_factory=dict)
    queries: Dict[str, QuerySpec] = field(default_factory=dict)
    timeout: Dict[str, str] = field(default_factory=dict)
    long_running: bool = False
    job_quota: Optional[Quota] = None
    failure_ok: bool = False
    replicable: bool = False
    max_replicas: Optional[int] = None
    require_success: bool = False
    priority_factor: Optional[float] = None
    priority_addend: Optional[int] = None
    priority: float = 0.0
    max_concurrent_jobs: Optional[int] = None
    max_spawn_jobs: int = 100
    max_spawn_jobs_period: Dict[str, Union[str, int]] = field(default_factory=lambda: {"minutes": 1})
    cache_dir: Optional[str] = None


@_dataclass_serial
class PipelineChildSpec:
    path: Optional[str] = None
    repos: Dict[str, str] = field(default_factory=dict)  # {child's name: our name}
    executors: Dict[str, str] = field(default_factory=dict)  # {task name: our executor's name}
    imports: Dict[str, "PipelineChildSpec"] = field(default_factory=dict)


@_dataclass_serial
class PipelineChildArgs:
    repos: Dict[str, Union[Dispatcher, "RepoClassSpec"]] = field(default_factory=dict)  # {child's name: dispatcher}
    executors: Dict[str, Optional[Dispatcher]] = field(default_factory=dict)  # {task name: our executor's name}
    imports: Dict[str, "PipelineChildArgs"] = field(default_factory=dict)

    def specify(self, prefix: str = "") -> Tuple[PipelineChildSpec, Dict[str, Dispatcher], Dict[str, Dispatcher]]:
        result = PipelineChildSpec()
        result_executors = {f"executor_{id(value)}": value for value in self.executors.values() if value is not None}
        result_repos = {f"{prefix}{name}": value for name, value in self.repos.items() if isinstance(value, Dispatcher)}
        result.executors = {
            f"{name}": f"executor_{id(value)}" for name, value in self.executors.items() if value is not None
        }
        result.repos = {f"{name}": f"{prefix}{name}" for name in self.repos}
        for imp_name, imp_args in self.imports.items():
            subresult, subrepos, subexecutors = imp_args.specify(prefix=f"{imp_name}_{prefix}")
            result.imports[imp_name] = subresult
            result_executors.update(subexecutors)
            for name, dispatcher in subrepos.items():
                if name in result_repos:
                    old_dispatcher = result_repos[name]
                    old_schema = old_dispatcher.args["schema"]
                    new_schema = dispatcher.args["schema"]
                    if old_schema is not None and new_schema is not None and old_schema != new_schema:
                        raise ValueError("Two classes for the same metadata repository have different schemas!")
                    dispatcher.args["schema"] = old_schema or new_schema
                result_repos[name] = dispatcher
        return result, result_repos, result_executors


@_dataclass_serial
class PipelineChildArgsMissing:
    my_name: str
    parent_name: str
    is_top: bool
    repos: Dict[str, "RepoClassSpec"] = field(default_factory=dict)  # {child's name: class spec}
    executors: Set[str] = field(default_factory=set)  # {task name}
    imports: Dict[str, "PipelineChildArgsMissing"] = field(default_factory=dict)

    def ready(self):
        return not self.repos and not self.executors and all(child.ready() for child in self.imports.values())

    def allocate(
        self, repo_allocators: Callable[["RepoClassSpec"], Optional[Dispatcher]], default_executor: Optional[Dispatcher]
    ) -> PipelineChildArgs:
        new_repos: Dict[str, Union[Dispatcher, RepoClassSpec]] = {}
        new_executors: Dict[str, Optional[Dispatcher]] = {}
        new_imports: Dict[str, PipelineChildArgs] = {}
        for repo_name, repo_spec in self.repos.items():
            if repo_spec.required and not self.is_top:
                raise ValueError(
                    f"{repo_name} is required (since it a repo_class from an imported pipeline) but is not fulfilled - importing {self.my_name} from {self.parent_name}"
                )
            repo_spec.name = repo_name
            result = repo_allocators(repo_spec)
            if result is None:
                raise ValueError("Repo allocators failed")
            new_repos[repo_name] = result

        for task_name in self.executors:
            if default_executor is None:
                raise ValueError("No default executor was provided")
            new_executors[task_name] = default_executor

        for imp_name, imp_missing in self.imports.items():
            if imp_missing.ready():
                continue
            new_imports[imp_name] = imp_missing.allocate(repo_allocators, default_executor)

        return PipelineChildArgs(new_repos, new_executors, new_imports)


@_dataclass_serial
class HostSpec:
    os: str


@_dataclass_serial
class RepoQuerySpec:
    cls: str
    query: str
    getters: Dict[str, str] = field(default_factory=dict)
    jq: Dict[str, str] = field(default_factory=dict)


@_dataclass_serial
class RepoClassSpec:
    cls: str
    compress_backend: Optional[bool] = None
    compress_backup: Optional[bool] = None
    schema: Optional[Dict[str, Any]] = None
    suffix: str = ""
    mimetype: str = "application/octet-stream"
    required: bool = True
    name: Optional[str] = None


@_dataclass_serial
class PipelineSpec:
    hosts: Dict[str, HostSpec] = field(default_factory=dict)
    tasks: Dict[str, TaskSpec] = field(default_factory=dict)
    executors: Dict[str, Dispatcher] = field(default_factory=dict)
    repos: Dict[str, Dispatcher] = field(default_factory=dict)
    repo_queries: Dict[str, RepoQuerySpec] = field(default_factory=dict)
    repo_classes: Dict[str, RepoClassSpec] = field(default_factory=dict)
    priorities: List[PriorityEntry] = field(default_factory=list)
    priority_factors: Dict[str, float] = field(default_factory=dict)
    priority_addends: Dict[str, float] = field(default_factory=dict)
    ephemerals: Dict[str, Dispatcher] = field(default_factory=dict)
    imports: Dict[str, PipelineChildSpec] = field(default_factory=dict)
    lockstep: str = ""
    agent_port: int = 6132
    agent_hosts: Dict[Optional[str], str] = field(default_factory=dict)
    agent_version: str = "unversioned"
    agent_secret: str = "insecure"
    long_running_timeout: Optional[float] = None
    global_template_env: Dict[str, str] = field(default_factory=dict)
    global_script_env: Dict[str, str] = field(default_factory=dict)
    max_job_quota: Optional[Quota] = None

    def desugar(self):
        query_repo_classes = {
            "Repository": "Query",
            "MetadataRepository": "QueryMetadata",
        }
        self.repos.update(
            {
                name: Dispatcher(
                    query_repo_classes[query_spec.cls],
                    {
                        "query": query_spec.query,
                        "getters": query_spec.getters,
                        "jq": query_spec.jq,
                    },
                )
                for name, query_spec in self.repo_queries.items()
            }
        )
        self.repo_queries.clear()

        for k, v in self.repo_classes.items():
            if isinstance(v, str):
                v = self.repo_classes[k] = RepoClassSpec(v)
            if v.compress_backend is None:
                v.compress_backend = v.cls == "FilesystemRepository"
            if v.compress_backup is None:
                v.compress_backup = v.cls == "FilesystemRepository"

        for taskname, task in self.tasks.items():
            for linkname, link in task.links.items():
                if link.jq_filter is not None:
                    repo_type = self._get_repo_type(link.repo)
                    if "Metadata" not in repo_type:  # guh
                        raise ValueError(f"Cannot use jq_filter with {repo_type}")
                    self.repos[f"autogen_{taskname}_{linkname}"] = Dispatcher(
                        "QueryMetadata",
                        {
                            "query": f"{link.repo}.filter[.jq]()",
                            "jq": {"jq": link.jq_filter},
                        },
                    )
                link.jq_filter = None

            if task.done is None:
                reponame = f"autodone_{taskname}"
                self.repo_classes[reponame] = RepoClassSpec(cls="MetadataRepository", required=False)
                task.done = reponame
            # horrid abstraction leak. that's sugar babey!
            if task.executable.cls == "Container" and "logs" not in task.executable.args:
                reponame = f"autologs_{taskname}"
                self.repo_classes[reponame] = RepoClassSpec(cls="BlobRepository", required=False)
                task.executable.args["logs"] = reponame
            if task.executable.cls == "ContainerSet" and "logs" not in task.executable.args:
                reponame = f"autologs_{taskname}"
                self.repo_classes[reponame] = RepoClassSpec(cls="BlobRepository", required=False)
                task.executable.args["logs"] = reponame
            if task.executable.cls == "Process" and "stdout" not in task.executable.args:
                reponame = f"autostdout_{taskname}"
                self.repo_classes[reponame] = RepoClassSpec(cls="BlobRepository", required=False)
                task.executable.args["stdout"] = reponame
                if "stderr" not in task.executable.args:
                    task.executable.args["stderr"] = "STDOUT"
            if task.job_quota is None and task.priority == 0.0:
                task.priority = 999999999

        for reponame, repo in self.repos.items():
            if repo.cls == "CokeyedJqFilterRepository":
                query = repo.args["filter_query"]
                source = repo.args["source"]
                filter_source = repo.args["filter_source"]
                source_defn = self._get_repo_type(source)
                if "Metadata" in source_defn:
                    query_cls = "QueryMetadata"
                elif "Filesystem" in source_defn:
                    query_cls = "QueryFilesystem"
                elif "Blob" in source_defn:
                    query_cls = "QueryBlob"
                else:
                    query_cls = "QueryRepository"
                self.repos[reponame] = Dispatcher(
                    query_cls,
                    {
                        "query": f"""
                        fn jq_filter_bool(data: Data) -> Bool: .jq_filter(data);
                        let filtered = {filter_source}.filter[.jq_filter_bool]();
                        fn my_filter(key: Key) -> Bool: filtered.contains(key);
                        {source}.filter[.my_filter]()
                    """,
                        "jq": {"jq_filter": query},
                    },
                )

    def _get_repo_type(self, name: str) -> str:
        if name in self.repos:
            return self.repos[name].cls
        if name in self.repo_classes:
            return self.repo_classes[name].cls
        raise KeyError(name)


@_dataclass_serial
class PipelineChild:
    pipeline: "PipelineStaging"
    repo_translation: Dict[str, str] = field(default_factory=dict)  # {imp name: {our name: child's name}}


# pylint: enable=missing-class-docstring,missing-function-docstring


class PipelineStaging:
    """The main manager for pipeline.yaml files.

    Instantiate this with the path to a pipeline.yaml file.
    """

    def __init__(
        self,
        config: Union[None, Path, PipelineSpec] = None,
        basedir: Optional[Path] = None,
        params: Optional[PipelineChildArgs] = None,
        is_top: Optional[bool] = True,
    ):
        """The basedir and params parameters are for internal use only."""
        self.children: Dict[str, PipelineStaging] = {}
        self.repos_fulfilled_by_parents: Dict[str, Dispatcher] = {}
        self.executors_fulfilled_by_parents: Dict[str, Dispatcher] = {}
        self.repos_promised_by_parents: Dict[str, RepoClassSpec] = {}
        self.executors_promised_by_parents: Set[str] = set()
        self.is_top = is_top

        if config is None:
            if basedir is None:
                raise TypeError("Must provide basedir if you don't provide filepath")

            self.filename = "pipeline.lock"
            self.basedir = basedir
            self.repos_fulfilled_by_parents = {}
            self.spec = PipelineSpec()
        else:
            if basedir is not None:
                raise TypeError("Cannot provide basedir if filepath is not None")

            if isinstance(config, Path):
                self.basedir = config.parent
                self.filename = config.name

                with open(config, "r", encoding="utf-8") as fp:
                    spec_dict = safe_load(fp)
                self.spec = PipelineSpec(**spec_dict)
                self.spec.desugar()
            else:
                self.spec = config
                self.basedir = Path(".")
                self.filename = "DOES_NOT_EXIST"  # um.

            if params is None:
                params = PipelineChildArgs()

            self.children = {}
            self.repos_fulfilled_by_parents = {k: v for k, v in params.repos.items() if isinstance(v, Dispatcher)}
            self.repos_promised_by_parents = {k: v for k, v in params.repos.items() if isinstance(v, RepoClassSpec)}
            self.executors_fulfilled_by_parents = {k: v for k, v in params.executors.items() if v is not None}
            self.executors_promised_by_parents = {k for k, v in params.executors.items() if v is None}

            for k, v in self.repos_promised_by_parents.items():
                if k in self.spec.repo_classes:
                    v2 = self.spec.repo_classes[k]
                    if v.cls != v2.cls:
                        raise ValueError(f"Disagreement on repo class for {k} in {self.filename}")
                    if v.schema is not None and v2.schema is not None and v.schema != v2.schema:
                        raise ValueError(f"Disagreement on schema for {k} in {self.filename}")
                    v2.schema = v.schema = v.schema or v2.schema

            unused = (
                (set(self.repos_fulfilled_by_parents) | set(self.repos_promised_by_parents))
                - set(self.spec.repos)
                - set(self.spec.repo_classes)
            )
            if unused:
                raise ValueError(f"Unused parameters to {self.basedir / self.filename}: {unused}")

            overlap = set(self.spec.repos) & set(self.spec.repo_classes)
            if overlap:
                raise ValueError(f"Overlapping repos and repo_classes in {self.basedir / self.filename}: {overlap}")

            for imp_name, imp in self.spec.imports.items():
                if imp.path is None:
                    raise TypeError("Import clause must specify path to import")
                child_params = self._reprocess_subimports(imp)
                if imp_name in params.imports:
                    child_params.executors.update(params.imports[imp_name].executors)
                    child_params.repos.update(params.imports[imp_name].repos)
                    child_params.imports.update(params.imports[imp_name].imports)

                self.children[imp_name] = PipelineStaging(
                    self.basedir / imp.path, params=child_params, is_top=None if self.is_top is None else False
                )

    def _get_repo(self, name: str) -> Union[Dispatcher, RepoClassSpec]:
        if name in self.repos_fulfilled_by_parents:
            return self.repos_fulfilled_by_parents[name]
        if name in self.spec.repos:
            return self.spec.repos[name]
        if name in self.repos_promised_by_parents:
            return self.repos_promised_by_parents[name]
        if name in self.spec.repo_classes:
            return self.spec.repo_classes[name]
        raise KeyError(name)

    def _get_executor(self, name: str) -> Optional[Dispatcher]:
        if name in self.executors_fulfilled_by_parents:
            return self.executors_fulfilled_by_parents[name]
        if name in self.spec.executors:
            return self.spec.executors[name]
        return None

    @staticmethod
    def _random_name() -> str:
        return bytes(random.randrange(256) for _ in range(8)).hex()

    def _reprocess_subimports(self, imp: PipelineChildSpec) -> PipelineChildArgs:
        return PipelineChildArgs(
            imports={subname: self._reprocess_subimports(subimp) for subname, subimp in imp.imports.items()},
            repos={param_name: self._get_repo(sat_name) for param_name, sat_name in imp.repos.items()},
            executors={param_name: self._get_executor(sat_name) for param_name, sat_name in imp.executors.items()},
        )

    def _get_priority(self, task: str, job: str, replica: int) -> float:
        result = 0.0

        for child in self._iter_children():
            for directive in child.spec.priorities:
                if (directive.job is None or directive.job == job) and (
                    directive.task is None or directive.task == task
                ):
                    result += directive.priority
            if task in child.spec.tasks:
                result += child.spec.tasks[task].priority
                addend = child.spec.tasks[task].priority_addend
                factor = child.spec.tasks[task].priority_factor
                if addend is not None:
                    assert addend >= 0, "Priority addend must be >= 0"
                    result -= addend * replica
                if factor is not None:
                    assert 0 < factor <= 1, "Priority factor must be 0 < x <= 1"
                    if result < 0:
                        result /= factor**replica
                    else:
                        result *= factor**replica
        return result

    def missing(self, parent_name: Optional[str] = None) -> PipelineChildArgsMissing:
        """Return a PipelineChildArgsMissing instance for this pipeline.yaml file.

        This object indicates which resources need to be allocated before the pipeline can be used. You can call its
        .ready() function to get a boolean for whether it is properly ready.
        """
        return PipelineChildArgsMissing(
            my_name=str(self.basedir / self.filename),
            parent_name=str(parent_name),
            is_top=True if self.is_top is None else self.is_top,
            repos={
                name: cls
                for name, cls in self.spec.repo_classes.items()
                if name not in self.repos_fulfilled_by_parents and name not in self.repos_promised_by_parents
            },
            executors={
                name
                for name, tspec in self.spec.tasks.items()
                if tspec.executor is None
                and name not in self.executors_fulfilled_by_parents
                and name not in self.executors_promised_by_parents
            },
            imports={name: child.missing(str(self.basedir / self.filename)) for name, child in self.children.items()},
        )

    def _iter_children(self) -> Iterator["PipelineStaging"]:
        yield self
        for child in self.children.values():
            yield from child._iter_children()

    def instantiate(self) -> Pipeline:
        """Convert a PipelineStaging into a Pipeline.

        This will fail if any resources need to be allocated.
        """
        missing = self.missing()
        if not missing.ready():
            raise ValueError("Cannot instantiate pipeline - missing definitions for repositories or executors")

        def nameit(d, name):
            d["name"] = name
            return d

        ephemeral_constructor = build_ephemeral_picker()
        repo_cache: Dict[int, Repository] = {}
        ephemeral_cache: Dict["PipelineStaging", Dict[str, Ephemeral[Any]]] = {}
        executor_cache: Dict[int, Executor] = {}
        all_tasks = []
        session = Session()
        global_template_env = {}
        global_script_env = {}
        for staging in self._iter_children():
            global_template_env.update(staging.spec.global_template_env)
            global_script_env.update(staging.spec.global_script_env)

            ephemerals = {
                name: session.ephemeral(ephemeral_constructor(asdict(value)), name=name)
                for name, value in staging.spec.ephemerals.items()
            }
            ephemeral_cache[staging] = ephemerals
            repo_constructor = build_repository_picker(ephemerals)
            repos = {name: repo_constructor(asdict(value)) for name, value in staging.spec.repos.items()}
            repo_cache.update({id(staging.spec.repos[name]): repo for name, repo in repos.items()})

            hosts = {name: host_constructor(nameit(asdict(val), name)) for name, val in staging.spec.hosts.items()}

            executor_constructor = build_executor_picker(hosts, ephemerals)
            executors = {name: executor_constructor(asdict(value)) for name, value in staging.spec.executors.items()}
            executor_cache.update({id(staging.spec.executors[name]): executor for name, executor in executors.items()})

        for staging in self._iter_children():
            all_repos = {name: repo_cache[id(dispatch)] for name, dispatch in staging.spec.repos.items()}
            all_local_repos = dict(all_repos)
            all_repos.update(
                {name: repo_cache[id(dispatch)] for name, dispatch in staging.repos_fulfilled_by_parents.items()}
            )
            for repo in all_local_repos.values():
                if isinstance(repo, QueryRepository):
                    repo.query.repos.update(all_repos)

            all_executors = {name: executor_cache[id(dispatch)] for name, dispatch in staging.spec.executors.items()}
            all_executors.update(
                {
                    name: executor_cache[id(dispatch)]
                    for name, dispatch in staging.executors_fulfilled_by_parents.items()
                }
            )
            task_constructor = build_task_picker(all_repos, all_executors, ephemeral_cache[staging])
            for task_name, task_spec in staging.spec.tasks.items():
                dict_spec = asdict(task_spec)
                if task_name in staging.executors_fulfilled_by_parents:
                    dict_spec["executor"] = task_name
                for link in dict_spec["links"].values():
                    link.pop("jq_filter")
                all_tasks.append(task_constructor(task_name, dict_spec))

        root_hosts = {name: host_constructor(nameit(asdict(val), name)) for name, val in self.spec.hosts.items()}
        mjq = None if self.spec.max_job_quota is None else quota_constructor(self.spec.max_job_quota)
        assert mjq is None or isinstance(mjq, Quota)
        return Pipeline(
            all_tasks,
            session,
            self._get_priority,
            agent_port=self.spec.agent_port,
            agent_hosts={
                root_hosts[name] if name is not None else None: val for name, val in self.spec.agent_hosts.items()
            },
            agent_secret=self.spec.agent_secret,
            agent_version=self.spec.agent_version,
            source_file=self.basedir / self.filename,
            long_running_timeout=(
                timedelta(minutes=self.spec.long_running_timeout)
                if self.spec.long_running_timeout is not None
                else None
            ),
            global_template_env=global_template_env,
            global_script_env=global_script_env,
            max_job_quota=mjq,
        )

    def allocate(
        self,
        repo_allocators: Callable[[RepoClassSpec], Optional[Dispatcher]],
        default_executor: Dispatcher,
        run_lockstep: bool = True,
    ) -> "PipelineStaging":
        """Lock a pipeline, generating a new PipelineStaging which imports this one and specifies all of its missing
        dependencies."""
        missing = self.missing()
        args = missing.allocate(repo_allocators, default_executor)
        spec, repos, executors = args.specify()
        for child in self._iter_children():
            if run_lockstep and child.spec.lockstep:
                if (
                    subprocess.run(
                        "set -e\n" + child.spec.lockstep, shell=True, cwd=child.basedir, check=False
                    ).returncode
                    != 0
                ):
                    raise Exception(
                        f"Could not lock pipeline: lockstep of {child.basedir / child.filename} failed:\n"
                        f"{child.spec.lockstep.strip()}"
                    )

        result = PipelineStaging(basedir=self.basedir)
        result.children["locked"] = PipelineStaging(
            self.spec, params=args, is_top=None if self.is_top is None else False
        )
        result.spec.repos.update(repos)
        result.spec.executors.update(executors)
        result.spec.imports["locked"] = spec
        result.spec.lockstep = "echo 'This is a lockfile - do not lock it' && false"
        result.spec.agent_port = random.randrange(0x4000, 0x8000)
        result.spec.agent_version = datetime.now().isoformat()
        result.spec.agent_secret = str(random.randint(10**40, 10**41))
        result.spec.agent_hosts = {}
        result.filename = str(Path(self.filename).with_suffix(".lock"))
        spec.path = str(self.basedir / self.filename)
        return result

    def save(self):
        """Save this spec back to the pipeline.yaml file, in case it has been modified."""
        spec_dict = asdict(self.spec)
        with open(self.basedir / self.filename, "w", encoding="utf-8") as fp:
            yaml.safe_dump(spec_dict, fp)


def find_config() -> Optional[Path]:
    """Discover a pipeline.yaml file in the current filesystem ancestry or $PIPELINE_YAML."""
    thing = os.getenv("PIPELINE_YAML")
    if thing is not None:
        return Path(thing)

    root = Path.cwd()
    while True:
        pth = root / "pipeline.yaml"
        if pth.exists():
            return pth
        newroot = root.parent
        if newroot == root:
            return None
        else:
            root = newroot


def get_current_directory_pipeline() -> Pipeline:
    cfgpath = find_config()
    if cfgpath is None:
        raise ValueError("Cannot find pipeline.yaml")
    lockfile = cfgpath.with_suffix(".lock")
    if lockfile.is_file():
        spec = PipelineStaging(lockfile)
    else:
        spec = PipelineStaging(cfgpath)
    if not spec.missing().ready():
        raise ValueError(
            "Cannot start this pipeline - it has unsatisfied dependencies. "
            "Try locking it with `python -m pydatatask.lock`"
        )

    pipeline = spec.instantiate()
    return pipeline
