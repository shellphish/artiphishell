"""This module houses the container manager executors."""

from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Tuple,
    cast,
)
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import chain
from pathlib import Path
import asyncio
import logging
import os

from aiodocker import DockerError
from kubernetes_asyncio.client import ApiException
import aiodocker.containers
import aiofiles.ospath
import dateutil.parser

from pydatatask.executor import Executor, pod_manager
from pydatatask.host import LOCAL_HOST, Host
from pydatatask.quota import Quota
from pydatatask.session import Ephemeral

if TYPE_CHECKING:
    from pydatatask.executor import pod_manager


l = logging.getLogger(__name__)


def docker_connect(url: Optional[str] = None):
    """Connect to a docker daemon.

    If url is provided, connect to the socket there. If not, connect to the default system daemon.
    """

    async def docker_connect_inner():
        async with aiodocker.Docker(url) as docker:
            yield docker

    return docker_connect_inner


class AbstractContainerManager(ABC, Executor):
    """The base class for container managers.

    Members of this class should be able to manage containers, including being able to track their lifecycles.
    """

    def __init__(self, quota: Quota, *, image_prefix: str = ""):
        super().__init__(quota)
        self._image_prefix = image_prefix

    @abstractmethod
    async def launch(
        self,
        task: str,
        job: str,
        replica: int,
        image: str,
        entrypoint: List[str],
        cmd: str,
        environ: Dict[str, str],
        quota: Quota,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
    ):
        """Launch a container with the given parameters.

        Mounts should be from localhost.
        """
        raise NotImplementedError

    @abstractmethod
    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        """Determine which containers from the given task (and optionally, the given job) are still live.

        Should return a dict mapping job id to job start time.
        """
        raise NotImplementedError

    @abstractmethod
    async def kill(self, task: str, job: str, replica: int):
        """Kill the container associated with the given task and job and replica.

        This does not need to be done gracefully by any stretch. It should wipe any resources associated with the job,
        so it does not show up as a finished task next time `update` is called.
        """
        raise NotImplementedError

    async def killall(self, task: str):
        """Kill all containers for the given task."""
        await asyncio.gather(*(self.kill(task, job, replica) for (job, replica) in await self.live(task)))

    @abstractmethod
    async def update(
        self, task: str, timeout: Optional[timedelta] = None
    ) -> Tuple[Dict[Tuple[str, int], datetime], Dict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]]]:
        """Perform routine maintenence on the running set of jobs for the given task.

        Should return a tuple of a the set of live replicas and a dict mapping finished job names to a tuple of the
        output logs from the job and a dict with any metadata left over from any replicas of the job.

        If any job has been alive for longer than timeout, kill it and return it as part of the finished jobs, not the
        live jobs.
        """
        raise NotImplementedError

    def to_container_manager(self) -> "AbstractContainerManager":
        return self


class DockerContainerManager(AbstractContainerManager):
    """A container manager for a docker installation.

    By default it will try to use the local docker unix socket. If you provide a socket URL to a dockerd hosted
    somewhere other than localhost, don't forget to specify the host parameter.
    """

    def __init__(
        self,
        quota: Quota,
        *,
        app: str = "pydatatask",
        docker: Ephemeral[aiodocker.Docker],
        host: Host = LOCAL_HOST,
        image_prefix: str = "",
        host_path_overrides: Optional[Dict[str, str]] = None,
    ):
        super().__init__(quota, image_prefix=image_prefix)
        self._docker = docker
        self.app = app
        self._host = host
        self._net = None
        self._host_path_overrides = host_path_overrides or {}
        self._host_path_overrides = {str(Path(x)).strip("/"): y for x, y in self._host_path_overrides.items()}
        self._deleted_containers = set()
        self._cached_containers: Optional[List[aiodocker.containers.DockerContainer]] = None
        self._lock = asyncio.Lock()

    async def _all_containers(self) -> List[aiodocker.containers.DockerContainer]:
        async with self._lock:
            if self._cached_containers is None:
                self._cached_containers = await self.docker.containers.list(all=1)
            return self._cached_containers

    def cache_flush(self):
        self._cached_containers = None

    @property
    def docker(self) -> aiodocker.Docker:
        """The aiodocker client instance associated with this executor."""
        return self._docker()

    @property
    def host(self):
        return self._host

    def _name_to_id(self, task: str, name: str) -> Optional[Tuple[str, int]]:
        name = name.strip("/")
        prefix = f"{self.app}___{task}___"
        if name.startswith(prefix):
            ident, replica = name[len(prefix) :].split("___")
            return ident, int(replica)
        return None

    def _id_to_name(self, task: str, ident: str, replica: int) -> str:
        return f"{self.app}___{task}___{ident}___{replica}"

    async def launch(
        self,
        task: str,
        job: str,
        replica: int,
        image: str,
        entrypoint: List[str],
        cmd: str,
        environ: Dict[str, str],
        quota: Quota,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
    ):
        if self._net is None:
            if await aiofiles.ospath.exists("/.dockerenv"):
                try:
                    hostname = cast(str, os.getenv("HOSTNAME"))
                    bytes.fromhex(hostname)
                except:  # pylint: disable=broad-except,bare-except
                    pass
                else:
                    self_container = await self.docker.containers.get(hostname)
                    self._net = self_container["HostConfig"]["NetworkMode"]

        config = {
            "Image": self._image_prefix + image,
            "AttachStdout": False,
            "AttachStderr": False,
            "AttachStdin": False,
            "OpenStdin": False,
            "Tty": tty,
            "Entrypoint": entrypoint,
            "Cmd": cmd,
            "Env": [f"{key}={val}" for key, val in environ.items()],
            "HostConfig": {
                "Binds": [
                    f"{self._host_path_overrides.get(str(Path(src)).strip('/'), src)}:{mountpoint}"
                    for mountpoint, src in mounts.items()
                ],
                "Privileged": privileged,
                "CpuQuota": int(quota.cpu * 100000),
                "CpuPeriod": 100000,
                "Memory": int(quota.mem),
            },
        }
        if self._net is not None:
            config["HostConfig"]["NetworkMode"] = self._net

        await self.docker.containers.run(config, name=self._id_to_name(task, job, replica))

    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        containers = await self._all_containers()

        live = [(info, self._name_to_id(task, info["Names"][0])) for info in containers]
        return {
            name: datetime.fromtimestamp(info["Created"], timezone.utc)
            for info, name in live
            if name is not None and (job is None or name[0] == job)
        }

    async def kill(self, task: str, job: str, replica: int):
        cont = await self.docker.containers.get(self._id_to_name(task, job, replica))
        try:
            await cont.stop(t=30)
        except aiodocker.exceptions.DockerError:
            pass
        await cont.delete()

    async def update(self, task: str, timeout: Optional[timedelta] = None):
        containers = [x for x in await self._all_containers() if x.id not in self._deleted_containers]
        infos_and_names = [(self._name_to_id(task, info["Names"][0]), info) for info in containers]
        dead = [
            (info, container, name)
            for (name, info), container in zip(infos_and_names, containers)
            if info["State"] in ("exited",) and name is not None
        ]
        now = datetime.now(tz=timezone.utc)
        timed_out = [
            (info, container, name)
            for (name, info), container in zip(infos_and_names, containers)
            if info["State"] not in ("exited",)
            and name is not None
            and timeout
            and now - datetime.fromtimestamp(info["Created"], timezone.utc) > timeout
        ]
        live_replicas = {
            name: datetime.fromtimestamp(info["Created"], timezone.utc)
            for (name, info), _ in zip(infos_and_names, containers)
            if info["State"] not in ("exited",)
            and name is not None
            and not (timeout and now - datetime.fromtimestamp(info["Created"], timezone.utc) > timeout)
        }
        live_jobs = {job for job, _ in live_replicas}
        await asyncio.gather(*(cont.stop(t=30) for _, cont, _ in timed_out), return_exceptions=True)
        results = await asyncio.gather(
            *(self._cleanup(container) for _, container, _ in dead),
            *(self._cleanup(container, True) for _, container, _ in timed_out),
        )
        final: DefaultDict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]] = defaultdict(dict)
        for (_, _, (job, replica)), result in zip(chain(dead, timed_out), results):
            if job not in live_jobs and result is not None:
                final[job][replica] = result

        return live_replicas, dict(final)

    async def _cleanup(
        self, container: aiodocker.containers.DockerContainer, timed_out: bool = False
    ) -> Optional[Tuple[Optional[bytes], Dict[str, Any]]]:
        mutated = aiodocker.containers.DockerContainer(container.docker, **container._container)
        try:
            log = "".join(
                line for line in await cast(Awaitable[List[str]], mutated.log(stdout=True, stderr=True))
            ).encode()
        except DockerError:
            l.warning("Failed to obtain logs", exc_info=True)
            log = None
        try:
            await mutated.delete()
            self._deleted_containers.add(mutated.id)
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        now = datetime.now(tz=timezone.utc)
        meta = {
            "success": not timed_out and mutated["State"]["ExitCode"] == 0,
            "start_time": dateutil.parser.isoparse(mutated["State"]["StartedAt"]),
            "end_time": now if timed_out else dateutil.parser.isoparse(mutated["State"]["FinishedAt"]),
            "timeout": timed_out,
            "exit_code": -1 if timed_out else mutated["State"]["ExitCode"],
            "image": mutated["Config"]["Image"],
        }
        return (log, meta)


class KubeContainerManager(AbstractContainerManager):
    """An executor that runs containers on a kubernetes cluster."""

    def __init__(self, quota, *, cluster: "pod_manager.PodManager", image_prefix: str = ""):
        super().__init__(quota, image_prefix=image_prefix)
        self.cluster = cluster

    @property
    def host(self):
        return self.cluster.host

    def _volume_lookup(self, provided_name: str) -> "pod_manager.VolumeSpec":
        if provided_name in self.cluster.volumes:
            return self.cluster.volumes[provided_name]
        return pod_manager.VolumeSpec.parse(provided_name)

    def cache_flush(self):
        super().cache_flush()
        self.cluster.cache_flush()

    def build_pod_spec(
        self,
        image: str,
        entrypoint: List[str],
        cmd: str,
        environ: Dict[str, str],
        quota: Quota,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
    ):
        mount_info = {
            provided_name: (
                str(Path(provided_name)).replace("/", "-").replace("_", "-").strip("-"),
                self._volume_lookup(str(Path(provided_name))),
            )
            for provided_name in mounts.values()
        }
        return {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "main",
                    "image": self._image_prefix + image,
                    "imagePullPolicy": "Always",
                    "command": entrypoint,
                    "args": [cmd],
                    "env": [{"name": name, "value": value} for name, value in environ.items()]
                    + [{"name": "NODE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}}],
                    "resources": {
                        "requests": {
                            "cpu": str(quota.cpu),
                            "memory": str(quota.mem),
                        },
                        "limits": {
                            "cpu": str(quota.cpu),
                            "memory": str(quota.mem),
                        },
                    },
                    "securityContext": {
                        "privileged": privileged,
                    },
                    "volumeMounts": [
                        {"mountPath": mountpoint, "name": mount_info[name][0]}
                        for mountpoint, name in mounts.items()
                        if not mount_info[name][1].null
                    ],
                    "tty": tty,
                    "stdin": tty,
                }
            ],
            "volumes": [info.to_kube(name) for (name, info) in mount_info.values() if not info.null],
        }

    async def launch(
        self,
        task: str,
        job: str,
        replica: int,
        image: str,
        entrypoint: List[str],
        cmd: str,
        environ: Dict[str, str],
        quota: Quota,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
    ):
        podspec = self.build_pod_spec(image, entrypoint, cmd, environ, quota, mounts, privileged, tty)
        await self.cluster.launch(
            task,
            job,
            replica,
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "spec": podspec,
            },
        )

    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        pods = await self.cluster.query(job, task)
        return {
            (pod.metadata.labels["job"], int(pod.metadata.labels["replica"])): pod.metadata.creation_timestamp
            for pod in pods
        }

    async def kill(self, task: str, job: str, replica: int):
        pods = await self.cluster.query(job, task, replica)
        for pod in pods:
            await self.cluster.delete(pod)

    async def update(self, task: str, timeout: Optional[timedelta] = None):
        pods = await self.cluster.query(job=None, task=task)
        finished_pods = [pod for pod in pods if pod.status.phase in ("Succeeded", "Failed")]
        now = datetime.now(tz=timezone.utc)
        timeout_pods = [
            pod
            for pod in pods
            if pod.status.phase not in ("Succeeded", "Failed")
            and timeout
            and now - pod.metadata.creation_timestamp > timeout
        ]
        live_replicas = {
            (pod.metadata.labels["job"], int(pod.metadata.labels["replica"])): pod.metadata.creation_timestamp
            for pod in pods
            if pod.status.phase not in ("Succeeded", "Failed")
            and not (timeout and now - pod.metadata.creation_timestamp > timeout)
        }
        live_jobs = {job for job, _ in live_replicas}
        results = await asyncio.gather(
            *chain((self._cleanup(pod) for pod in finished_pods), (self._cleanup(pod, True) for pod in timeout_pods))
        )
        final: DefaultDict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]] = defaultdict(dict)
        for pod, result in zip(chain(finished_pods, timeout_pods), results):
            job = pod.metadata.labels["job"]
            replica = int(pod.metadata.labels["replica"])
            if job not in live_jobs:
                final[job][replica] = result
            elif result[0] is not None:
                directory = f"/tmp/pydatatask-emergency/{task}-{job}"
                l.error(
                    "Unexpected replica death %s:%s#%s (%s) - writing logs to %s",
                    task,
                    job,
                    replica,
                    pod.metadata.name,
                    directory,
                )
                os.makedirs(directory, exist_ok=True)
                with open(f"{directory}/{replica}", "wb") as fp:
                    fp.write(result[0])
        return live_replicas, dict(final)

    async def _cleanup(self, pod, timeout: bool = False) -> Tuple[bytes, Dict[str, Any]]:
        try:
            log = await self.cluster.logs(pod)
        except (TimeoutError, ApiException, asyncio.exceptions.TimeoutError):
            log = b"<Timeout or other error retrieving logs>"
        await self.cluster.delete(pod)
        return (
            log,
            {
                "reason": pod.status.phase if not timeout else "Timeout",
                "timeout": timeout,
                "start_time": pod.metadata.creation_timestamp,
                "end_time": datetime.now(tz=timezone.utc),
                "image": pod.status.container_statuses[0].image,
                "node": pod.spec.node_name,
                "success": pod.status.phase == "Succeeded" and not timeout,
            },
        )
