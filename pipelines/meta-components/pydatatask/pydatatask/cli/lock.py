from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)
from pathlib import Path
import argparse
import asyncio
import functools
import getpass
import os
import random
import shutil
import string
import sys
import tempfile
import urllib.parse

import aiodocker

from pydatatask.executor.pod_manager import VolumeSpec
from pydatatask.executor.proc_manager import LocalLinuxManager
from pydatatask.host import Host, HostOS
from pydatatask.pipeline import Pipeline
from pydatatask.quota import LOCALHOST_QUOTA
from pydatatask.session import Session
from pydatatask.staging import Dispatcher, PipelineStaging, RepoClassSpec, find_config

LOCK_ID = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
LOCK_PATH = Path(f"{os.environ.get('TEMP', '/tmp')}/pydatatask-{getpass.getuser()}/lock-{LOCK_ID}")

EPHEMERALS: Dict[Any, Tuple[str, Dispatcher]] = {}

T = TypeVar("T")

# issues for future Audrey:
# - quotas aren't deduplicated, nor can they be without some new interfaces


class Allocator:
    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        raise NotImplementedError


class TempAllocator(Allocator):
    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        if spec.cls == "MetadataRepository":
            return Dispatcher("InProcessMetadata", {})
        if spec.cls == "BlobRepository":
            return Dispatcher("InProcessBlob", {})
        if spec.cls == "FilesystemRepository":
            return Dispatcher("Tarfile", {"inner": {"cls": "InProcessBlob", "args": {}}})
        return None


class LocalAllocator(Allocator):
    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        path = LOCK_PATH
        path.mkdir(exist_ok=True, parents=True)
        basedir = tempfile.mkdtemp(dir=path)
        if spec.cls == "MetadataRepository":
            result = Dispatcher("YamlFile", {"basedir": basedir})
        elif spec.cls == "BlobRepository":
            if spec.compress_backend:
                result = Dispatcher(
                    "CompressedBlob", {"inner": {"cls": "File", "args": {"basedir": basedir, "extension": ".gz"}}}
                )
            else:
                result = Dispatcher("File", {"basedir": basedir})
        elif spec.cls == "FilesystemRepository":
            if spec.compress_backend:
                result = Dispatcher("Tarfile", {"inner": {"cls": "File", "args": {"basedir": basedir}}})
            else:
                result = Dispatcher("Directory", {"basedir": basedir})
        else:
            return None
        result.args["compress_backup"] = spec.compress_backup
        result.args["schema"] = spec.schema
        return result


class S3BlobAllocator(Allocator):
    def __init__(self, url: str):
        self.url = url
        try:
            self.scheme, rest = self.url.split("://", 1)
            self.username, rest = rest.split(":", 1)
            self.password, rest = rest.split("@", 1)
            self.host, rest = rest.split("/", 1)
            if "/" in rest:
                self.bucket, self.prefix = rest.split("/", 1)
            else:
                self.bucket = rest
                self.prefix = ""
        except ValueError as e:
            raise Exception("Failed to parse s3 bucket url: see --help for expected format") from e

    def make_ephemeral(self):
        client_key = ("s3", self.scheme, self.username, self.password, self.host)
        if client_key not in EPHEMERALS:
            # could maybe do with a better name than just host...
            EPHEMERALS[client_key] = (
                self.host,
                Dispatcher(
                    "S3Connection",
                    {"endpoint": f"{self.scheme}://{self.host}", "username": self.username, "password": self.password},
                ),
            )
        return EPHEMERALS[client_key][0]

    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        if spec.cls != "BlobRepository":
            return None
        return self._allocate_blob(spec)

    def _allocate_blob(self, spec: RepoClassSpec) -> Dispatcher:
        return Dispatcher(
            "S3Bucket",
            {
                "client": self.make_ephemeral(),
                "bucket": self.bucket,
                "prefix": f"{self.prefix}lock-{LOCK_ID}/{spec.name}/",
                "suffix": spec.suffix,
                "mimetype": spec.mimetype,
            },
        )


class S3FsAllocator(S3BlobAllocator):
    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        if spec.cls != "FilesystemRepository":
            return None

        return Dispatcher(
            "Tarfile",
            {
                "inner": self._allocate_blob(spec),
            },
        )


class MongoMetaAllocator(Allocator):
    def __init__(self, url: str):
        self.url, self.database = url.split(":::", 1)

    def make_ephemeral(self):
        client_key = ("mongo", self.url, self.database)
        if client_key not in EPHEMERALS:
            # see above
            EPHEMERALS[client_key] = (
                urllib.parse.urlparse(self.url).hostname or "",
                Dispatcher("MongoDatabase", {"url": self.url, "database": self.database}),
            )
        return EPHEMERALS[client_key][0]

    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        if spec.cls != "MetadataRepository":
            return None
        return Dispatcher(
            "MongoMetadata",
            {
                "database": self.make_ephemeral(),
                "collection": f"lock-{LOCK_ID}.{spec.name}",
            },
        )


class S3FallbackMongoMetaAllocator(Allocator):
    def __init__(self, url: str):
        mongo_url, s3_url = url.split(":::::", 1)
        self.s3_alloc = S3BlobAllocator(s3_url)
        self.mongo_alloc = MongoMetaAllocator(mongo_url)

    def allocate(self, spec: RepoClassSpec) -> Optional[Dispatcher]:
        if spec.cls != "MetadataRepository":
            return None
        s3_name = None if spec.name is None else spec.name + "___s3"
        s3 = self.s3_alloc.allocate(RepoClassSpec("BlobRepository", name=s3_name))
        assert s3 is not None
        s3.cls = "YamlMetadataS3Bucket"
        return Dispatcher(
            "FallbackMetadata",
            {
                "base": self.mongo_alloc.allocate(spec),
                "fallback": s3,
            },
        )


def _subargparse(url: str):
    result: Dict[str, Union[bool, str]] = {}
    for arg in url.split(","):
        if not arg:
            continue
        if "=" in arg:
            k, v = arg.split("=", 1)
            result[k] = v
        else:
            result[arg] = True
    return result


def parse_quota(thing: str):
    cpu, mem = thing.split("/")
    return {"cpu": cpu, "mem": mem}


def parse_host(thing: str):
    os, hostname = thing.split("/")
    return Host(
        hostname,
        {
            "linux": HostOS.Linux,
        }[os.lower()],
    )


def parse_volumespec_dict(thing: str):
    things = thing.split("::")
    result = {}
    for thing in things:
        key, val = thing.split(":")
        if val == "Null":
            result[key] = VolumeSpec(null=True)
        else:
            ty, val = val.split("@")
            if ty == "HostPath":
                result[key] = VolumeSpec(host_path=val)
            elif ty == "Pvc":
                result[key] = VolumeSpec(pvc=val)
            else:
                raise ValueError(f"Bad volume type {ty}")
    return result


def subargparse(**outer_kwargs) -> Callable[[Callable[..., T]], Callable[[str], T]]:
    def outer(f):
        @functools.wraps(f)
        def inner(url):
            try:
                inner_kwargs = {}
                args = _subargparse(url)
                for name, constructor in outer_kwargs.items():
                    arg = args.pop(name, None)
                    if arg is not None:
                        inner_kwargs[name] = constructor(arg)
                if args:
                    print(f"Warning: unused subargument{'' if len(args) == 1 else 's'} {', '.join(args)}")
                return f(**inner_kwargs)
            except Exception as e:  # pylint: disable=broad-exception-caught
                raise Exception("weh") from e

        setattr(inner, "argstr", ", ".join(outer_kwargs))
        return inner

    return outer


@subargparse(quota=parse_quota)
def local_exec_allocator(quota=None):
    LOCK_PATH.mkdir(exist_ok=True, parents=True)
    dargs: Dict[str, Any] = {
        "nil_ephemeral": "nil_ephemeral",
        "local_path": str(LOCK_PATH),
    }
    if quota is not None:
        dargs["quota"] = quota

    def inner(*, name, image_prefix, **kwargs):
        dargs["app"] = name
        dargs["image_prefix"] = image_prefix
        return Dispatcher("LocalLinux", dict(dargs))

    return inner


@subargparse(
    local_quota=parse_quota,
    kube_quota=parse_quota,
    namespace=str,
    kube_host=parse_host,
    kube_context=str,
    kube_volumes=parse_volumespec_dict,
)
def local_exec_kube_allocator(
    local_quota=None, kube_quota=None, namespace=None, kube_host=None, kube_context=None, kube_volumes=None
):
    LOCK_PATH.mkdir(exist_ok=True, parents=True)
    dargs = {
        "nil_ephemeral": "nil_ephemeral",
        "local_path": str(LOCK_PATH),
    }
    if local_quota is not None:
        dargs["quota"] = local_quota
    if kube_quota is not None:
        dargs["kube_quota"] = kube_quota
    if namespace is not None:
        dargs["kube_namespace"] = namespace
    if kube_host is not None:
        dargs["kube_host"] = kube_host
    if kube_context is not None:
        dargs["kube_context"] = kube_context
    if kube_volumes is not None:
        dargs["kube_volumes"] = kube_volumes

    def inner(*, name, image_prefix, **kwargs):
        dargs["app"] = name
        dargs["image_prefix"] = image_prefix
        return Dispatcher("LocalLinuxOrKube", dict(dargs))

    return inner


async def get_ip() -> str:
    docker = None
    try:
        docker = aiodocker.Docker()
        return (await (await docker.networks.get("bridge")).show())["IPAM"]["Config"][0]["Gateway"]
    except:
        return "127.0.0.1"
    finally:
        if docker is not None:
            await docker.close()


def walk_obj(obj: Any, duplicates: bool = False, seen: Optional[Set[int]] = None) -> Iterator[Tuple[Any, List[Any]]]:
    if seen is None:
        seen = set()
    results: Dict[int, Any] = {}
    if isinstance(obj, list):
        results.update({id(x): x for x in obj})
    if isinstance(obj, dict):
        results.update({id(x): x for x in obj.keys()})
        results.update({id(x): x for x in obj.values()})
    if hasattr(obj, "__dict__"):
        results.update({id(x): x for x in obj.__dict__.values()})
    if hasattr(obj, "__slots__"):
        results.update({id(x): x for x in obj.__slots__})  # type: ignore
    for ident in seen:
        results.pop(ident, None)
    if duplicates:
        new_seen = seen | set(results)
    else:
        new_seen = seen
        seen.update(results)
    output = list(results.values())
    yield obj, output
    for sub in output:
        yield from walk_obj(sub, duplicates, new_seen)


async def kill_all(pipeline: Pipeline):
    async with pipeline:
        await pipeline.kill_all()


def main():
    parser = argparse.ArgumentParser(
        description="Produce a lockfile allocating executors and repositories for a given pipeline"
    )
    parser.add_argument(
        "--repo-local",
        action="append_const",
        dest="repo_allocator",
        const=LocalAllocator(),
        help="Allocate repositories on local filesystem",
    )
    parser.add_argument(
        "--repo-blob-s3",
        action="append",
        dest="repo_allocator",
        type=S3BlobAllocator,
        help="Allocate blob repositories on an s3 bucket. Expects url in format scheme://username:password@host/bucket/prefix",
    )
    parser.add_argument(
        "--repo-fs-s3",
        action="append",
        dest="repo_allocator",
        type=S3FsAllocator,
        help="Allocate filesystem repositories as a tarball in an s3 bucket. Expects url in format scheme://username:password@host/bucket/prefix",
    )
    parser.add_argument(
        "--repo-meta-mongo",
        action="append",
        dest="repo_allocator",
        type=MongoMetaAllocator,
        help="Allocate metadata repositories as an entry in a mongodb collection. Expects url in format MONGO_URL:::database",
    )
    parser.add_argument(
        "--repo-meta-mongo-s3-fallback",
        action="append",
        dest="repo_allocator",
        type=S3FallbackMongoMetaAllocator,
        help="Allocate metadata repositories as an entry in a mongodb collection, or as a yaml-encoded blob in a s3 bucket if it cannot be stored for any reason. Expects url in format a:::::b, where a is the argument to --repo-meta-mongo and b is the argument to --repo-blob-s3",
    )
    parser.add_argument(
        "--repo-temp",
        action="append_const",
        dest="repo_allocator",
        const=TempAllocator(),
        help="Allocate repositories in-memory",
    )
    parser.add_argument(
        "--exec-local",
        dest="executor",
        type=local_exec_allocator,
        help=f"Run tasks on the local machine. Takes subarguments: {getattr(local_exec_allocator, 'argstr')}",
    )
    parser.add_argument(
        "--exec-local-or-kube",
        dest="executor",
        type=local_exec_kube_allocator,
        help=f"Run tasks on the local machine or the kubernetes cluster configured for access from the local machine. Takes subarguments: {getattr(local_exec_kube_allocator, 'argstr')}",
    )
    parser.add_argument("--name", help="The name of the app for automatically generated executors")
    parser.add_argument(
        "--long-running-timeout",
        help="Cap the execution of long running tasks to the given number of minutes",
        type=float,
    )
    parser.add_argument(
        "--image-prefix",
        help="Force container executors to schedule containers with images that are prefixed with this string.",
        type=str,
        default="",
    )
    parser.add_argument(
        "--unlock",
        action="store_true",
        help="Tear down resources associated with the current lockfile, but don't set up a new lockfile",
    )
    parser.add_argument(
        "--no-launch-agent",
        action="store_true",
        help="Inhibit launching the HTTP agent on localhost",
    )
    parser.add_argument(
        "--no-lockstep",
        action="store_true",
        help="Inhibit running lockstep tasks specified in pipeline files",
    )
    parser.add_argument(
        "--global-template-env",
        action="append",
        default=[],
        help="Add a value (KEY=VALUE) to the template environment for the entire pipeline",
    )
    parser.add_argument(
        "--global-script-env",
        action="append",
        default=[],
        help="Add a value (KEY=VALUE) to the shell environment for every task with a templatable shell script. This value is not escaped; do your own escaping.",
    )
    parser.add_argument(
        "--agent-host",
        help="Specify the default hostname the agent will be running at",
    )
    parser.add_argument(
        "--agent-port",
        type=int,
        help="Specify the port the agent will be running at",
    )
    parser.add_argument(
        "--ignore-required",
        action="store_true",
        help="Allocate all missing repos - do not respect the required: True attribute",
    )
    parser.add_argument(
        "--max-job-quota",
        type=parse_quota,
        help="Set the resources which will be consumed by a job which requests maximum quota",
    )
    parsed = parser.parse_args()

    if not parsed.repo_allocator:
        parsed.repo_allocator = [LocalAllocator()]

    def allocators(spec: RepoClassSpec) -> Dispatcher:
        for allocator in parsed.repo_allocator:
            result = allocator.allocate(spec)
            if result is not None:
                return result
        raise ValueError("Could not allocate %s: tried %s" % (spec, parsed.repo_allocator))

    session = Session()

    @session.ephemeral
    async def nil_ephemeral():
        yield None

    cfgpath = find_config()
    if cfgpath is None:
        print("Cannot find pipeline.yaml", file=sys.stderr)
        return 1
    name = parsed.name or cfgpath.parent.name
    lockfile = cfgpath.with_suffix(".lock")
    if lockfile.exists():
        try:
            locked = PipelineStaging(lockfile)
            pipeline = locked.instantiate()
        except:  # pylint: disable=bare-except
            print(
                "Could not load lockfile.\n"
                "This could indicate that either your version of pydatatask or the pipeline.yaml have changed.\n"
                "In order to manually clean up before deleting the lockfile, you should:\n\n"
                "- kill any live worker processes, containers, pods, etc\n"
                "- kill any running agents\n"
                "- delete all filepaths mentioned in the lockfile\n"
            )
            sys.exit(1)

        asyncio.run(kill_all(pipeline))

        # HACK
        executor = LocalLinuxManager(
            quota=LOCALHOST_QUOTA, app=name, image_prefix=parsed.image_prefix, nil_ephemeral=nil_ephemeral
        )
        asyncio.run(executor.teardown_agent())

        # HACK
        for obj, _ in walk_obj(locked.spec.repos):
            if (
                isinstance(obj, (str, Path))
                and str(obj).startswith(f"{os.environ.get('TEMP', '/tmp')}/pydatatask")
                and os.path.exists(obj)
            ):
                shutil.rmtree(obj)

        lockfile.unlink()
        if parsed.unlock:
            return
    else:
        if parsed.unlock:
            print("Error: no lockfile to unlock")
            return 1

    spec = PipelineStaging(cfgpath, is_top=None if parsed.ignore_required else True)
    locked = spec.allocate(
        allocators,
        (parsed.executor or local_exec_allocator(""))(**parsed.__dict__),
        run_lockstep=not parsed.no_lockstep,
    )
    locked.filename = lockfile.name
    locked.spec.long_running_timeout = parsed.long_running_timeout
    locked.spec.agent_hosts[None] = asyncio.run(get_ip()) if parsed.agent_host is None else parsed.agent_host
    if parsed.agent_port is not None:
        locked.spec.agent_port = parsed.agent_port
    locked.spec.global_template_env.update(
        {k: v for k, v in [line.split("=", 1) for line in parsed.global_template_env]}
    )
    locked.spec.global_script_env.update({k: v for k, v in [line.split("=", 1) for line in parsed.global_script_env]})
    locked.spec.ephemerals.update(dict(EPHEMERALS.values()))
    locked.spec.ephemerals["nil_ephemeral"] = Dispatcher("Nil", {})
    locked.spec.max_job_quota = parsed.max_job_quota
    locked.save()

    locked = PipelineStaging(locked.basedir / locked.filename)
    pipeline = locked.instantiate()

    # HACK
    if not parsed.no_launch_agent:
        executor = LocalLinuxManager(
            quota=LOCALHOST_QUOTA, app=name, image_prefix=parsed.image_prefix, nil_ephemeral=nil_ephemeral
        )
        asyncio.run(executor.launch_agent(pipeline))

    print(locked.basedir / locked.filename)


if __name__ == "__main__":
    sys.exit(main())
