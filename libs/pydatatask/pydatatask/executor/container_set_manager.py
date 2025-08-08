from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple
from abc import abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import asyncio
import random
import string

from kubernetes_asyncio.client import ApiException
import aiodocker

from pydatatask.executor import Executor, pod_manager
from pydatatask.executor.container_manager import (
    DockerContainerManager,
    KubeContainerManager,
)
from pydatatask.host import LOCAL_HOST, Host
from pydatatask.quota import Quota, QuotaPoolSet, QuotaReservation
from pydatatask.session import Ephemeral

import logging
import aiohttp

l = logging.getLogger(__name__)

class AbstractContainerSetManager(Executor):
    def __init__(self, quota: Quota, *, image_prefix: str = ""):
        super().__init__(quota)
        self._image_prefix = image_prefix

    @abstractmethod
    async def size(self) -> int:
        """Retrieve the number of instances that will be launched for each replica, i.e. the number of machines we
        will be running on."""
        raise NotImplementedError

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
        resource_limits: Quota | None,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
        **kwargs,
    ):
        """Launch a container set with the given parameters.

        Mounts should be from localhost.
        """
        raise NotImplementedError

    @abstractmethod
    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        """Determine which container sets from the given task (and optionally, the given job) are still live.

        Should return a dict mapping job id to job start time.
        """
        raise NotImplementedError

    @abstractmethod
    async def kill(self, task: str, job: str, replica: int | None):
        """Kill the container set associated with the given task and job and replica.

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

    @property
    def single_node_quota(self) -> Quota:
        return self.quota

    async def collect_logs(self, task: str, job: str, replica: int | None) -> Dict[int, bytes]:
        return {}


class DockerContainerSetManager(AbstractContainerSetManager):
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
        super().__init__(quota)
        self._docker_manager = DockerContainerManager(
            quota,
            app=app + "-set",
            docker=docker,
            host=host,
            image_prefix=image_prefix,
            host_path_overrides=host_path_overrides,
        )

    async def size(self):
        return 1

    @property
    def host(self):
        return self._docker_manager.host

    def cache_flush(self, soft=False):
        self._docker_manager.cache_flush(soft=soft)

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
        resource_limits: Quota | None,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
        **kwargs,
    ):
        return await self._docker_manager.launch(
            task, job, replica, image, entrypoint, cmd, environ, quota, resource_limits, mounts, privileged, tty
        )

    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        return await self._docker_manager.live(task, job)

    async def kill(self, task: str, job: str, replica: int | None):
        return await self._docker_manager.kill(task, job, replica)

    async def update(
        self, task: str, timeout: Optional[timedelta] = None
    ) -> Tuple[Dict[Tuple[str, int], datetime], Dict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]]]:
        return await self._docker_manager.update(task, timeout)


class KubeContainerSetManager(AbstractContainerSetManager):
    def __init__(self, inner: KubeContainerManager):
        super().__init__(inner.quota)
        self.inner = inner
        self._connection = inner.cluster._connection
        self._cached_ds = None
        self.namespace = inner.cluster.namespace
        self.app = inner.cluster.app + "-set"
        self._lock = asyncio.Lock()

    async def size(self):
        return len(await self.inner.cluster.get_nodes())

    @property
    def connection(self) -> pod_manager.KubeConnection:
        """The ephemeral connection.

        This function will fail is the connection is provided by an unopened session.
        """
        return self._connection()

    @property
    def api(self) -> Any:
        """The current API client."""
        return self.connection.api

    @property
    def api_ws(self) -> Any:
        """The current websocket-aware API client."""
        return self.connection.api_ws

    @property
    def v1(self) -> Any:
        """A CoreV1Api instance associated with the current API client."""
        return self.connection.v1

    @property
    def v1_ws(self) -> Any:
        """A CoreV1Api instance associated with the current websocket-aware API client."""
        return self.connection.v1_ws

    @property
    def v1apps(self) -> Any:
        """A CoreV1Api instance associated with the current API client."""
        return self.connection.v1apps


    async def query(self, job=None, task=None, replica=None) -> List[Any]:
        async with self._lock:
            if self._cached_ds is None:
                self._cached_ds = await self.inner.cluster._list_namespaced_daemonsets(f"app={self.app}")

        assert self._cached_ds is not None
        return [
            ds
            for ds in self._cached_ds
            if (job is None or ds.metadata.labels["job"] == job)
            and (task is None or ds.metadata.labels["task"] == task)
            and (replica is None or ds.metadata.labels["replica"] == str(replica))
        ]

    async def delete(self, ds: Any, max_retries: int = 10):
        """Destroy the given ds."""
        try:
            await self.inner.cluster._delete_namespaced_daemon_set(ds.metadata.name, max_retries)
        except ApiException:
            pass

    async def logs(self, ds: Any, timeout=30) -> bytes:
        """Retrieve the logs for the given ds."""
        nonce = ds.spec.selector.match_labels["daemonset"]
        pods = await self.inner.cluster._list_namespaced_pods(f"daemonset={nonce}", max_retries=0)
        all_logs = await asyncio.gather(
            *(
                self.inner.cluster._read_namespaced_pod_log(pod.metadata.name, timeout, max_retries=0)
                for pod in pods
            )
        )
        return "\n".join(f"==> {pod.status.host_ip} <==\n" + log for pod, log in zip(pods, all_logs)).encode()

    def cache_flush(self, soft=False):
        self.inner.cache_flush(soft=soft)
        self._cached_ds = None

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
        resource_limits: Quota | None,
        mounts: Dict[str, str],
        privileged: bool,
        tty: bool,
        reservation: Optional[QuotaReservation] = None,
        wait_for_image_pull: bool = False,
        **kwargs,
    ):
        pod_spec = self.inner.build_pod_spec(image, entrypoint, cmd, environ, quota, resource_limits, mounts, privileged, tty, reservation, wait_for_image_pull=wait_for_image_pull)
        pod_spec["restartPolicy"] = "Always"
        pod_spec["priorityClassName"] = "high-priority"
        nonce = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
        pod_template = {
            "metadata": {
                "labels": {
                    "daemonset": nonce,
                    "app": self.app,
                    "task": task,
                    "job": job,
                    "replica": str(replica),
                },
            },
            "spec": pod_spec,
        }
        ds = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": self._id_to_name(task, job, replica),
                "labels": {
                    "app": self.app,
                    "task": task,
                    "job": job,
                    "replica": str(replica),
                },
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "daemonset": nonce,
                    },
                },
                "template": pod_template,
            },
        }

        await self.inner.cluster._create_namespaced_daemon_set(ds)

    def _id_to_name(self, task: str, job: str, replica: int) -> str:
        if replica is None:
            replica = '0'
        task = task.replace("_", "-")
        return f"{self.app}-{task}-{job}-{replica}"

    def _ds_to_id(self, ds: Any) -> Tuple[str, int]:
        return ds.metadata.labels["job"], int(ds.metadata.labels["replica"])

    async def collect_logs(self, task: str, job: str, replica: int | None) -> Dict[int, bytes]:
        ds = await self.query(job, task, replica)
        results = await asyncio.gather(*(self.logs(ds) for ds in ds))
        final: Dict[int, bytes] = {}
        for ds, result in zip(ds, results):
            final[int(ds.metadata.labels["replica"])] = result
        return final

    async def update(
        self, task: str, timeout: Optional[timedelta] = None
    ) -> Tuple[Dict[Tuple[str, int], datetime], Dict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]]]:
        """Do maintainence.

        This is easier because container sets are naturally long living.
        """
        dss = await self.query(task=task)
        dsmap = {self._ds_to_id(ds): ds for ds in dss}
        live = set(dsmap)
        dead: Set[Tuple[str, int]] = set()
        now = datetime.now(tz=timezone.utc)
        timed = {
            name for name in live if timeout is not None and dsmap[name].metadata.creation_timestamp + timeout < now
        }
        live -= timed
        dead |= timed
        live_jobs = {name[0] for name in live}

        def gen_done(ds):
            return {
                "reason": "Timeout",
                "start_time": ds.metadata.creation_timestamp,
                "end_time": datetime.now(tz=timezone.utc),
                "timeout": True,
                "success": True,
            }

        async def io_guy(name) -> Optional[bytes]:
            try:
                return await self.logs(dsmap[name])
            except (TimeoutError, ApiException, Exception):
                return None

        logs = await asyncio.gather(
            *(io_guy(name) for name in dead if name[0] not in live_jobs),
            return_exceptions=True,
        )
        await asyncio.gather(
            *(self.inner.cluster._delete_namespaced_daemon_set(dsmap[name].metadata.name) for name in dead),
            return_exceptions=True,
        )

        live_result = {name: dsmap[name].metadata.creation_timestamp for name in live}
        reap_result: DefaultDict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]] = defaultdict(dict)
        for name, log in zip(dead, logs):
            if isinstance(log, Exception) or log is None:
                log = b"<Timeout or other error retrieving logs>"

            job, replica = name
            if job not in live_jobs:
                reap_result[job][replica] = (log, gen_done(dsmap[name]))

        return live_result, dict(reap_result)

    async def kill(self, task: str, job: str, replica: int | None):
        """Killllllllllllll."""
        d_id = self._id_to_name(task, job, replica or 0)
        l.debug(f"💀👿 Killing daemonset: {d_id}")

        try:
            await self.inner.cluster._delete_namespaced_daemon_set(d_id)
        except ApiException:
            pass

    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        dss = await self.query(task=task, job=job)
        return {self._ds_to_id(ds): ds.metadata.creation_timestamp for ds in dss}

    @property
    def host(self):
        return self.inner.host

    @property
    def quota_pools(self) -> "QuotaPoolSet":
        return self.inner.quota_pools
