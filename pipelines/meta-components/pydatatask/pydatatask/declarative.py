"""This module contains parsing methods for transforming various dict and list schemas into Repository, Task, and
other kinds of pydatatask classes."""

from typing import Any, Callable, Dict, List, Mapping, Optional, Type, TypeVar, Union
from datetime import timedelta
from enum import Enum
from pathlib import Path
import base64
import gc
import json
import os
import socket
import sys
import traceback

from importlib_metadata import entry_points
import aiobotocore.config
import aiobotocore.session
import asyncssh
import docker_registry_client_async
import motor.motor_asyncio

from pydatatask.executor import Executor
from pydatatask.executor.container_manager import DockerContainerManager, docker_connect
from pydatatask.executor.pod_manager import PodManager, VolumeSpec, kube_connect
from pydatatask.executor.proc_manager import (
    InProcessLocalLinuxManager,
    LocalLinuxManager,
    LocalLinuxOrKubeManager,
    SSHLinuxManager,
)
from pydatatask.host import Host, HostOS
from pydatatask.query.parser import QueryValueType, tyexpr_basic_to_type
from pydatatask.query.query import Query
from pydatatask.query.repository import (
    QueryBlobRepository,
    QueryFilesystemRepository,
    QueryMetadataRepository,
    QueryRepository,
)
from pydatatask.quota import MAX_QUOTA, Quota, _MaxQuotaType
from pydatatask.repository import (
    DirectoryRepository,
    DockerRepository,
    FallbackMetadataRepository,
    FileRepository,
    InProcessBlobRepository,
    InProcessMetadataRepository,
    MongoMetadataRepository,
    Repository,
    S3BucketRepository,
    YamlMetadataFileRepository,
    YamlMetadataS3Repository,
)
from pydatatask.repository.base import CompressedBlobRepository
from pydatatask.repository.filesystem import TarfileFilesystemRepository
from pydatatask.session import Ephemeral
from pydatatask.task import (
    ContainerSetTask,
    ContainerTask,
    KubeTask,
    LinkKind,
    ProcessTask,
    Task,
)
import pydatatask

_T = TypeVar("_T")


def _nil_eph():
    async def nil_eph():
        yield None

    return nil_eph


def parse_bool(thing: Any) -> bool:
    """Parse a string, int, or bool into a bool."""
    if isinstance(thing, bool):
        return thing
    if isinstance(thing, int):
        return bool(thing)
    if isinstance(thing, str):
        if thing.lower() in ("yes", "y", "1", "true"):
            return True
        if thing.lower() in ("no", "n", "0", "false"):
            return False
        raise ValueError(f"Invalid bool value {thing}")
    raise ValueError(f"{type(thing)} is not valid as a bool")


def parse_optional_bool(thing: Any) -> Optional[bool]:
    """Parse a string, int, bool, or None into a bool or None."""
    if thing is None:
        return None
    return parse_bool(thing)


_E = TypeVar("_E", bound=Enum)


def make_enum_constructor(cls: Type[_E]) -> Callable[[Any], Optional[_E]]:
    """Parse a string into an enum."""

    def inner(thing):
        if thing is None:
            return None
        if not isinstance(thing, str):
            raise ValueError(f"{cls} must be instantiated by a string")
        return getattr(cls, thing)

    return inner


def make_constructor(name: str, constructor: Callable[..., _T], schema: Dict[str, Any]) -> Callable[[Any], _T]:
    """Generate a constructor function, or a function which will take a dict of parameters, validate them, and call
    a function with them as keywords."""
    tdc = make_typeddict_constructor(name, schema)

    def inner(thing):
        return constructor(**tdc(thing))

    return inner


def make_typeddict_constructor(name: str, schema: Dict[str, Any]) -> Callable[[Any], Dict[str, Any]]:
    """Generate a dict constructor function, or a function which will take a dict of parameters, validate and
    transform them according to a schema, and return that dict."""

    def inner(thing):
        if not isinstance(thing, dict):
            raise ValueError(f"{name} must be followed by a mapping")

        kwargs = {}
        for k, v in thing.items():
            if k not in schema:
                raise ValueError(f"Invalid argument to {name}: {k}")
            kwargs[k] = schema[k](v)
        return kwargs

    return inner


def make_dispatcher(name: str, mapping: Dict[str, Callable[[Any], _T]]) -> Callable[[Any], _T]:
    """Generate a dispatcher function, or a function which accepts a mapping of two keys: cls and args.

    cls should be one keys in the provided mapping, and args are the arguments to the function pulled out of mapping.
    Should be used for situations where you need to pick from one of many implementations of something.
    """

    def inner(thing):
        if not isinstance(thing, dict):
            raise ValueError(f"{name} must be a mapping")
        if "cls" not in thing:
            raise ValueError(f"You must provide the cls name for {name}")
        key = thing["cls"]
        value = thing.get("args", {})
        constructor = mapping.get(key, None)
        if constructor is None:
            raise ValueError(f"{key} is not a valid member of {name}")
        return constructor(value)

    return inner


def make_dict_parser(
    name: str, key_parser: Callable[[str], str], value_parser: Callable[[Any], _T]
) -> Callable[[Any], Dict[str, _T]]:
    """Generate a dict parser function, or a function which validates and transforms the keys and values of a dict
    into another dict."""

    def inner(thing):
        if not isinstance(thing, dict):
            raise ValueError(f"{name} must be a dict")
        return {key_parser(key): value_parser(value) for key, value in thing.items()}

    return inner


def make_list_parser(name: str, value_parser: Callable[[Any], _T]) -> Callable[[Any], List[_T]]:
    """Generate a list parser function, or a function which validates and transforms the members of a list into
    another list."""

    def inner(thing):
        if not isinstance(thing, list):
            raise ValueError(f"{name} must be a list")
        return [value_parser(value) for value in thing]

    return inner


def make_picker(name: str, options: Mapping[str, _T]) -> Callable[[Any], Optional[_T]]:
    """Generate a picker function, or a function which takes a string and returns one of the members of the provided
    options dict."""

    def inner(thing):
        if thing is None:
            return None
        if not options:
            raise ValueError(f"Must provide at least one {name}")
        if not isinstance(thing, str):
            raise ValueError(f"When picking a {name}, must provide a str")
        if thing not in options:
            raise ValueError(
                f"{name}: {thing} is not a valid option for {options}, you want e.g. {next(iter(options))}"
            )
        return options[thing]

    return inner


def _build_s3_connection(endpoint: str, username: str, password: str):
    async def minio():
        minio_session = aiobotocore.session.get_session()
        async with minio_session.create_client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=username,
            aws_secret_access_key=password,
        ) as client:
            yield client

    return minio


def _build_docker_connection(
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    config_file: Optional[str] = None,
    default_config_file: bool = False,
):
    if default_config_file:
        config_file = os.path.expanduser("~/.docker/config.json")
    if config_file is not None:
        with open(config_file, "r", encoding="utf-8") as fp:
            docker_config = json.load(fp)
        username, password = base64.b64decode(docker_config["auths"][domain]["auth"]).decode().split(":")
    else:
        if username is None or password is None:
            raise ValueError("Must provide username and password or a config file for DockerRegistry")

    async def docker():
        registry = docker_registry_client_async.DockerRegistryClientAsync(
            client_session_kwargs={"connector_owner": True},
            tcp_connector_kwargs={"family": socket.AF_INET},
            ssl=True,
        )
        await registry.add_credentials(
            credentials=base64.b64encode(f"{username}:{password}".encode()).decode(),
            endpoint=domain,
        )
        yield registry
        await registry.close()
        gc.collect()

    return docker


def _build_mongo_connection(url: str, database: str):
    async def mongo():
        client = motor.motor_asyncio.AsyncIOMotorClient(url)
        collection = client.get_database(database)
        yield collection

    return mongo


def _build_ssh_connection(
    hostname: str, username: str, password: Optional[str] = None, key: Optional[str] = None, port: int = 22
):
    async def ssh():
        async with asyncssh.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            client_keys=asyncssh.load_keypairs(key) if key is not None else None,
        ) as s:
            yield s

    return ssh


quota_constructor_inner = make_constructor("quota", Quota.parse, {"cpu": str, "mem": str})


def quota_constructor(thing: Any) -> Union[Quota, _MaxQuotaType]:
    if thing == "MAX":
        return MAX_QUOTA
    if thing.get("max", None):
        return _MaxQuotaType(float(thing["max"]))
    return quota_constructor_inner(thing)


timedelta_constructor = make_constructor(
    "timedelta",
    timedelta,
    {"days": int, "seconds": int, "microseconds": int, "milliseconds": int, "minutes": int, "hours": int, "weeks": int},
)


def make_annotated_constructor(
    name: str, constructor: Callable[..., _T], schema: Dict[str, Any]
) -> Callable[[Any], _T]:
    """Generate a constructor which allows the passing of an "annotations" key even if the constructor does not take
    one."""

    def inner_constructor(**kwargs):
        annotations = kwargs.pop("annotations", {})
        compress = kwargs.pop("compress_backup", False)
        schema = kwargs.pop("schema", None)
        max_concurrent_jobs = kwargs.pop("max_concurrent_jobs", None)
        max_spawn_jobs = kwargs.pop("max_spawn_jobs", None)
        max_spawn_jobs_period = kwargs.pop("max_spawn_jobs_period", None)
        require_success = kwargs.pop("require_success", None)
        result = constructor(**kwargs)
        result.annotations.update(annotations)  # type: ignore
        # sketchy...
        if compress:
            result.compress_backup = compress  # type: ignore
        if schema:
            result.schema = schema  # type: ignore
        if max_concurrent_jobs:
            result.max_concurrent_jobs = max_concurrent_jobs  # type: ignore
        if max_spawn_jobs:
            result.max_spawn_jobs = max_spawn_jobs  # type: ignore
        if max_spawn_jobs_period:
            result.max_spawn_jobs_period = max_spawn_jobs_period  # type: ignore
        if require_success:
            result.require_success = require_success  # type: ignore
        return result

    schema["annotations"] = lambda x: x
    schema["compress_backup"] = lambda x: x
    schema["schema"] = lambda x: x
    schema["max_concurrent_jobs"] = lambda x: x
    schema["max_spawn_jobs"] = lambda x: x
    schema["max_spawn_jobs_period"] = timedelta_constructor
    schema["require_success"] = parse_bool
    return make_constructor(name, inner_constructor, schema)


volumespec_constructor = make_constructor(
    "VolumeSpec",
    VolumeSpec,
    {
        "pvc": lambda thing: thing if thing is None else str(thing),
        "host_path": lambda thing: thing if thing is None else str(thing),
        "null": parse_bool,
    },
)


def build_repository_picker(ephemerals: Mapping[str, Callable[[], Any]]) -> Callable[[Any], Repository]:
    """Generate a function which will dispatch a dict into all known repository constructors.

    This function can be extended through the ``pydatatask.repository_constructors`` entrypoint.
    """
    kinds: Dict[str, Callable[[Any], Repository]] = {}
    kinds.update(
        {
            "InProcessMetadata": make_annotated_constructor(
                "InProcessMetadataRepository",
                InProcessMetadataRepository,
                {},
            ),
            "InProcessBlob": make_annotated_constructor(
                "InProcessBlobRepository",
                InProcessBlobRepository,
                {},
            ),
            "File": make_annotated_constructor(
                "FileRepository",
                FileRepository,
                {
                    "basedir": str,
                    "extension": str,
                    "case_insensitive": parse_bool,
                },
            ),
            "Tarfile": make_annotated_constructor(
                "TarfileFilesystemRepository",
                TarfileFilesystemRepository,
                {
                    "inner": make_dispatcher("Repository", kinds),
                },
            ),
            "CompressedBlob": make_annotated_constructor(
                "CompressedBlobRepository",
                CompressedBlobRepository,
                {
                    "inner": make_dispatcher("Repository", kinds),
                },
            ),
            "Directory": make_annotated_constructor(
                "DirectoryRepository",
                DirectoryRepository,
                {
                    "basedir": str,
                    "extension": str,
                    "case_insensitive": parse_bool,
                    "discard_empty": parse_bool,
                },
            ),
            "YamlFile": make_annotated_constructor(
                "YamlMetadataFileRepository",
                YamlMetadataFileRepository,
                {
                    "basedir": str,
                    "extension": str,
                    "case_insensitive": parse_bool,
                },
            ),
            "S3Bucket": make_annotated_constructor(
                "S3BucketRepository",
                S3BucketRepository,
                {
                    "client": make_picker("S3Connection", ephemerals),
                    "bucket": str,
                    "prefix": str,
                    "suffix": str,
                    "mimetype": str,
                    "incluster_endpoint": str,
                },
            ),
            "YamlMetadataS3Bucket": make_annotated_constructor(
                "YamlMetadataS3Repository",
                YamlMetadataS3Repository,
                {
                    "client": make_picker("S3Connection", ephemerals),
                    "bucket": str,
                    "prefix": str,
                    "suffix": str,
                    "mimetype": str,
                    "incluster_endpoint": str,
                },
            ),
            "DockerRegistry": make_annotated_constructor(
                "DockerRepository",
                DockerRepository,
                {
                    "registry": make_picker("DockerRegistry", ephemerals),
                    "domain": str,
                    "repository": str,
                },
            ),
            "MongoMetadata": make_annotated_constructor(
                "MongoMetadataRepository",
                MongoMetadataRepository,
                {
                    "database": make_picker("MongoDatabase", ephemerals),
                    "collection": str,
                },
            ),
            "FallbackMetadata": make_annotated_constructor(
                "FallbackMetadata",
                FallbackMetadataRepository,
                {
                    "base": make_dispatcher("Repository", kinds),
                    "fallback": make_dispatcher("Repository", kinds),
                },
            ),
            "Query": make_annotated_constructor(
                "QueryRepository",
                QueryRepository,
                {
                    "query": str,
                    "getters": make_dict_parser("getters", str, tyexpr_basic_to_type),
                    "jq": make_dict_parser("jq", str, str),
                },
            ),
            "QueryMetadata": make_annotated_constructor(
                "QueryMetadataRepository",
                QueryMetadataRepository,
                {
                    "query": str,
                    "getters": make_dict_parser("getters", str, tyexpr_basic_to_type),
                    "jq": make_dict_parser("jq", str, str),
                },
            ),
            "QueryBlob": make_annotated_constructor(
                "QueryBlobRepository",
                QueryBlobRepository,
                {
                    "query": str,
                    "getters": make_dict_parser("getters", str, tyexpr_basic_to_type),
                    "jq": make_dict_parser("jq", str, str),
                },
            ),
            "QueryFilesystem": make_annotated_constructor(
                "QueryFilesystemRepository",
                QueryFilesystemRepository,
                {
                    "query": str,
                    "getters": make_dict_parser("getters", str, tyexpr_basic_to_type),
                    "jq": make_dict_parser("jq", str, str),
                },
            ),
        }
    )
    for ep in entry_points(group="pydatatask.repository_constructors"):
        maker = ep.load()
        try:
            kinds.update(maker(ephemerals))
        except TypeError:
            traceback.print_exc(file=sys.stderr)
    return make_dispatcher("Repository", kinds)


def build_executor_picker(hosts: Dict[str, Host], ephemerals: Dict[str, Ephemeral[Any]]) -> Callable[[Any], Executor]:
    """Generate a function which will dispatch a dict into all known executor constructors.

    This function can be extended through the ``pydatatask.executor_constructors`` entrypoint.
    """
    nil_picker = make_picker("None", ephemerals)
    kinds: Dict[str, Callable[[Any], Executor]] = {
        "TempLinux": make_constructor(
            "InProcessLocalLinuxManager",
            InProcessLocalLinuxManager,
            {
                "quota": quota_constructor,
                "app": str,
                "local_path": str,
            },
        ),
        "LocalLinux": make_constructor(
            "LocalLinuxManager",
            LocalLinuxManager,
            {
                "quota": quota_constructor,
                "app": str,
                "local_path": str,
                "image_prefix": str,
                "nil_ephemeral": lambda thing: None if thing is None else nil_picker(thing),
            },
        ),
        "LocalLinuxOrKube": make_constructor(
            "LocalLinuxOrKubeManager",
            LocalLinuxOrKubeManager,
            {
                "quota": quota_constructor,
                "app": str,
                "local_path": str,
                "image_prefix": str,
                "nil_ephemeral": lambda thing: None if thing is None else nil_picker(thing),
                "kube_namespace": lambda thing: None if thing is None else str(thing),
                "kube_host": make_picker("Host", hosts),
                "kube_quota": quota_constructor,
                "kube_context": lambda thing: thing,
                "kube_volumes": make_dict_parser("kube_volumes", str, volumespec_constructor),
            },
        ),
        "SSHLinux": make_constructor(
            "SSHLinuxManager",
            SSHLinuxManager,
            {
                "quota": quota_constructor,
                "host": make_picker("Host", hosts),
                "app": str,
                "remote_path": str,
                "ssh": make_picker("SSHConnection", ephemerals),
            },
        ),
        "Kubernetes": make_constructor(
            "PodManager",
            PodManager,
            {
                "quota": quota_constructor,
                "host": make_picker("Host", hosts),
                "app": str,
                "namespace": lambda thing: None if thing is None else str(thing),
                "connection": make_picker("KubeConnection", ephemerals),
                "volumes": make_dict_parser("volumes", str, volumespec_constructor),
            },
        ),
        "Docker": make_constructor(
            "DockerContainerManager",
            DockerContainerManager,
            {
                "quota": quota_constructor,
                "host": make_picker("Host", hosts),
                "app": str,
                "docker": make_picker("DockerConnection", ephemerals),
                "image_prefix": str,
            },
        ),
    }
    for ep in entry_points(group="pydatatask.executor_constructors"):
        maker = ep.load()
        try:
            kinds.update(maker(ephemerals))
        except TypeError:
            traceback.print_exc(file=sys.stderr)
    return make_dispatcher("Executor", kinds)


host_constructor = make_constructor(
    "Host",
    Host,
    {
        "name": str,
        "os": make_enum_constructor(HostOS),
    },
)


def build_ephemeral_picker() -> Callable[[Any], Ephemeral[Any]]:
    """Generate a function which will dispatch a dict into all known ephemeral constructors.

    This function can be extended through the ``pydatatask.ephemeral_constructors`` entrypoint.
    """
    kinds = {
        "S3Connection": make_constructor(
            "S3Connection",
            _build_s3_connection,
            {
                "endpoint": str,
                "username": str,
                "password": str,
            },
        ),
        "DockerRegistry": make_constructor(
            "DockerRegistry",
            _build_docker_connection,
            {
                "domain": str,
                "username": str,
                "password": str,
                "config_file": str,
                "default_config_file": parse_bool,
            },
        ),
        "MongoDatabase": make_constructor(
            "MongoDatabase",
            _build_mongo_connection,
            {
                "url": str,
                "database": str,
            },
        ),
        "SSHConnection": make_constructor(
            "SSHConnection",
            _build_ssh_connection,
            {
                "hostname": str,
                "username": str,
                "password": str,
                "key": str,
                "port": int,
            },
        ),
        "KubeConnection": make_constructor(
            "KubeConnection",
            kube_connect,
            {
                "config_file": str,
                "context": str,
            },
        ),
        "DockerConnection": make_constructor(
            "DockerConnection",
            docker_connect,
            {
                "url": lambda thing: thing,
            },
        ),
        "Nil": lambda x: _nil_eph(),
    }
    for ep in entry_points(group="pydatatask.ephemeral_constructors"):
        maker = ep.load()
        try:
            kinds.update(maker())
        except TypeError:
            traceback.print_exc(file=sys.stderr)
    return make_dispatcher("Ephemeral", kinds)


link_kind_constructor = make_enum_constructor(LinkKind)


def build_task_picker(
    repos: Dict[str, Repository],
    executors: Dict[str, Executor],
    ephemerals: Mapping[str, Callable[[], Any]],
) -> Callable[[str, Any], Task]:
    """Generate a function which will dispatch a dict into all known task constructors.

    This function can be extended through the ``pydatatask.task_constructors`` entrypoint.
    """
    link_constructor = make_typeddict_constructor(
        "Link",
        {
            "repo": make_picker("Repository", repos),
            "kind": link_kind_constructor,
            "key": lambda thing: None if thing is None else str(thing),
            "cokeyed": lambda thing: {x: repos[y] for x, y in thing.items()},
            "auto_meta": lambda thing: str(thing) if thing is not None else None,
            "auto_values": lambda thing: thing,
            "is_input": parse_optional_bool,
            "is_output": parse_optional_bool,
            "is_status": parse_optional_bool,
            "inhibits_start": parse_optional_bool,
            "required_for_start": parse_optional_bool,
            "inhibits_output": parse_optional_bool,
            "required_for_success": parse_optional_bool,
            "force_path": lambda thing: str(thing) if thing is not None else None,
            "DANGEROUS_filename_is_key": parse_optional_bool,
            "content_keyed_md5": parse_optional_bool,
            "equals": lambda thing: None if thing is None else str(thing),
        },
    )
    links_constructor = make_dict_parser("links", str, link_constructor)

    def query_maker(
        result_type: QueryValueType,
        query: str,
        parameters: Dict[str, QueryValueType],
        getters: Dict[str, QueryValueType],
        jq: Dict[str, str],
    ) -> Any:
        return Query(result_type, query, parameters, getters, repos, jq)

    query_constructor = make_constructor(
        "Query",
        query_maker,
        {
            "result_type": tyexpr_basic_to_type,
            "query": str,
            "parameters": make_dict_parser("parameters", str, tyexpr_basic_to_type),
            "getters": make_dict_parser("getters", str, tyexpr_basic_to_type),
            "jq": make_dict_parser("jq", str, str),
        },
    )
    queries_constructor = make_dict_parser("queries", str, query_constructor)

    def mk_container_wrapper(initial):
        def container_wrapper(thing):
            if "host_mounts" in thing:
                mounts = thing.pop("mounts", {})
                mounts.update(thing.pop("host_mounts", {}))
                mounts = {str(Path(k)): v for k, v in mounts.items()}
                thing["mounts"] = mounts
            return initial(thing)

        return container_wrapper

    kinds = {
        "Process": make_annotated_constructor(
            "ProcessTask",
            ProcessTask,
            {
                # fmt: off
                # Common to all tasks
                "name": str,
                "executor": make_picker("Executor", executors),
                "done": make_picker("Repository", repos),
                "ready": make_picker("Repository", repos),
                "links": links_constructor,
                "queries": queries_constructor,
                "timeout": timedelta_constructor,
                "long_running": parse_bool,
                "failure_ok": parse_bool,
                "replicable": parse_bool,
                "max_replicas": lambda thing: None if thing is None else int(thing),
                "cache_dir": lambda thing: thing,

                # Process-specific
                "template": str,
                "environ": make_dict_parser("environ", str, str),
                "job_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "stdin": make_picker("Repository", repos),
                "stdout": make_picker("Repository", repos),
                "stderr": lambda thing: pydatatask.task.STDOUT
                if thing == "STDOUT"
                else make_picker("Repository", repos)(thing),
                # fmt: on
            },
        ),
        "Kubernetes": make_annotated_constructor(
            "KubeTask",
            KubeTask,
            {
                # fmt: off
                # Common to all tasks
                "name": str,
                "executor": make_picker("Executor", executors),
                "done": make_picker("Repository", repos),
                "ready": make_picker("Repository", repos),
                "links": links_constructor,
                "queries": queries_constructor,
                "timeout": timedelta_constructor,
                "long_running": parse_bool,
                "failure_ok": parse_bool,
                "replicable": parse_bool,
                "max_replicas": lambda thing: None if thing is None else int(thing),
                "cache_dir": lambda thing: thing,

                # Kube-specific
                "job_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "template": str,
                "template_env": make_dict_parser("environ", str, str),
                "logs": make_picker("Repository", repos),
                # fmt: on
            },
        ),
        "Container": mk_container_wrapper(
            make_annotated_constructor(
                "ContainerTask",
                ContainerTask,
                {
                    # fmt: off
                # Common to all tasks
                "name": str,
                "executor": make_picker("Executor", executors),
                "done": make_picker("Repository", repos),
                "ready": make_picker("Repository", repos),
                "links": links_constructor,
                "queries": queries_constructor,
                "timeout": timedelta_constructor,
                "long_running": parse_bool,
                "failure_ok": parse_bool,
                "replicable": parse_bool,
                "max_replicas": lambda thing: None if thing is None else int(thing),
                "cache_dir": lambda thing: thing,

                # Container-specific
                "template": str,
                "image": str,
                "environ": make_dict_parser("environ", str, str),
                "entrypoint": make_list_parser("entrypoint", str),
                "job_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "fallback_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "logs": make_picker("Repository", repos),
                "privileged": parse_bool,
                "tty": parse_bool,
                "mounts": make_dict_parser("mounts", str, str),
                    # fmt: on
                },
            )
        ),
        "ContainerSet": mk_container_wrapper(
            make_annotated_constructor(
                "ContainerSetTask",
                ContainerSetTask,
                {
                    # fmt: off
                # Common to all tasks
                "name": str,
                "executor": make_picker("Executor", executors),
                "done": make_picker("Repository", repos),
                "ready": make_picker("Repository", repos),
                "links": links_constructor,
                "queries": queries_constructor,
                "timeout": timedelta_constructor,
                "long_running": parse_bool,
                "failure_ok": parse_bool,
                "replicable": parse_bool,
                "max_replicas": lambda thing: None if thing is None else int(thing),
                "cache_dir": lambda thing: thing,

                # Containerset-specific
                "template": str,
                "image": str,
                "environ": make_dict_parser("environ", str, str),
                "entrypoint": make_list_parser("entrypoint", str),
                "job_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "fallback_quota": lambda thing: None if thing is None else quota_constructor(thing),
                "logs": make_picker("Repository", repos),
                "privileged": parse_bool,
                "tty": parse_bool,
                "mounts": make_dict_parser("mounts", str, str),
                    # fmt: on
                },
            )
        ),
    }
    for ep in entry_points(group="pydatatask.task_constructors"):
        maker = ep.load()
        try:
            kinds.update(maker(repos, ephemerals))
        except TypeError:
            traceback.print_exc(file=sys.stderr)
    dispatcher = make_dispatcher("Task", kinds)

    def constructor(name, thing):
        thing.pop("priority")
        thing.pop("priority_factor")
        thing.pop("priority_addend")
        executable = thing.pop("executable")
        executable["args"].update(thing)
        executable["args"]["name"] = name
        try:
            links = links_constructor(executable["args"].pop("links", {}) or {})
            task = dispatcher(executable)
            for linkname, link in links.items():
                task.link(linkname, **link)
        except Exception:
            print(f"### Error constructing task {name}: ", file=sys.stderr)
            raise

        return task

    return constructor
