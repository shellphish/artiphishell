"""In order for a `KubeTask` or a subclass to connect, authenticate, and manage pods in a kubernetes cluster, it
needs several resource references.

the `PodManager` simplifies tracking the lifetimes of these resources.
"""

import os
import time

from typing import (
    Any,
    AsyncIterator,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Tuple,
    Awaitable,
)
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import asyncio
import logging

from kubernetes_asyncio.client import ApiClient, ApiException, AppsV1Api, CoreV1Api
from kubernetes_asyncio.config import (
    ConfigException,
    load_incluster_config,
    load_kube_config,
)
from kubernetes_asyncio.config.kube_config import Configuration
from kubernetes_asyncio.stream import WsApiClient
from typing_extensions import Self

from pydatatask.executor import Executor
from pydatatask.executor.container_manager import KubeContainerManager
from pydatatask.host import Host, KubeHostNode
from pydatatask.quota import Quota, QuotaPoolSet, NodeQuota, QuotaPool
from pydatatask.session import Ephemeral

import aiohttp

l = logging.getLogger(__name__)

__all__ = ("PodManager", "KubeConnection", "kube_connect")


class KubeConnection:
    """A connection to a kubernetes cluster.

    Used as an argument to PodManager in order to separate the async bits from the sync bits. If you're loading
    configuration from standard paths, then rather than instantiating one directly, you should use kube_connect.
    """

    def __init__(self, config: Configuration, incluster: bool = False):
        self.api: ApiClient = ApiClient(config)
        self.api_ws: WsApiClient = WsApiClient(config)
        self.v1 = CoreV1Api(self.api)
        self.v1_ws = CoreV1Api(self.api_ws)
        self.v1apps = AppsV1Api(self.api)
        self.incluster = incluster

    async def close(self):
        """Clean up the connection."""
        await self.api.close()
        await self.api_ws.close()


def kube_connect(
    config_file: Optional[str] = None, context: Optional[str] = None
) -> Callable[[], AsyncIterator[KubeConnection]]:
    """Load kuberenetes configuration from standard paths and generate a KubeConnection based on it.

    This should be used like so:

    .. code:: python

        session = Session()
        kube_connection = session.ephemeral(kube_connect(...))
        pod_manager = PodManager(..., connection=kube_connection)
    """

    async def inner():
        config = type.__call__(Configuration)
        try:
            load_incluster_config(config)
            incluster = True
        except ConfigException:
            loader = await load_kube_config(config_file, context)
            await loader.load_and_set(config)
            incluster = False
        connection = KubeConnection(config, incluster)
        yield connection
        await connection.close()

    return inner


@dataclass
class VolumeSpec:
    pvc: Optional[str] = None
    host_path: Optional[str] = None
    null: bool = False

    @classmethod
    def parse(cls, data: str) -> Self:
        if "/" in data:
            return cls(host_path=data)
        return cls(pvc=data)

    def to_kube(self, name: str) -> Dict[str, Any]:
        if self.pvc is not None:
            return {"name": name, "persistentVolumeClaim": {"claimName": self.pvc}}
        if self.host_path is not None:
            return {"name": name, "hostPath": {"path": self.host_path}}
        assert self.null
        raise Exception("VolumeSpec is null")


class PodManager(Executor):
    """A pod manager allows multiple tasks to share a connection to a kubernetes cluster and manage pods on it."""

    def to_pod_manager(self) -> "PodManager":
        return self

    def to_container_manager(self):
        return KubeContainerManager(self.quota, cluster=self)

    def __init__(
        self,
        quota: Quota,
        host: Host,
        app: str,
        namespace: Optional[str],
        connection: Ephemeral[KubeConnection],
        volumes: Optional[Dict[str, VolumeSpec]] = None,
        quota_pools: Optional[QuotaPoolSet] = None,
    ):
        """
        :param app: The app name string with which to label all created pods.
        :param namespace: The namespace in which to create and query pods.
        :param config: Optional: A callable returning a kubernetes configuration object. If not provided, will attempt
                                 to use the "default" configuration, i.e. what is available after calling
                                 ``await kubernetes_asyncio.config.load_kube_config()``.
        """
        super().__init__(quota)
        self.single_node_quota = quota
        self._host = host
        self.app = app
        self._quota_pools = quota_pools or QuotaPoolSet.get_localhost_quota_pool()
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as fp:
                default_namespace = fp.read().strip()
        except FileNotFoundError:
            default_namespace = "default"
        self.namespace = namespace or default_namespace
        self._connection = connection
        self.volumes = volumes or {}
        self._cached_pods: Optional[List[Any]] = None
        self._cached_nodes: Optional[List[Any]] = None
        self._lock = asyncio.Lock()

        self.pod_cache_last_updated: Optional[int] = None
        self.pod_cache_ttl: Optional[int] = None
        self.pod_cache_enabled: bool = True
    
    @property
    def quota_pools(self) -> QuotaPoolSet:
        return self._quota_pools

    def cache_flush(self, soft=False):
        super().cache_flush(soft=soft)
        self._cached_pods = None
        self._cached_nodes = None
        self.pod_cache_last_updated = None

    @property
    def host(self):
        return self._host

    @property
    def connection(self) -> KubeConnection:
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


    async def get_nodes(self):
        async with self._lock:
            # WARN: This function may race with the cache clearing, so we need to atomically update self._cached_nodes
            cached_nodes = self._cached_nodes
            if cached_nodes is None:
                cached_nodes = await self._list_nodes('kubernetes.azure.com/mode!=system')
            self._cached_nodes = cached_nodes

        assert cached_nodes is not None
        return cached_nodes

    async def refresh_quota_pools(self):
        """
        Using information from the kubernetes API, refresh the available quota pools.
        """

        nodes = await self.get_nodes()

        node_hosts = [KubeHostNode(node) for node in nodes]

        smallest_node_quota = None

        nodes_with_quota = []
        num_concurrent_tasks = int(os.environ.get("NUM_CONCURRENT_TASKS", 1)) if 'NUM_CONCURRENT_TASKS' in os.environ else None
        my_task = int(os.environ.get("CRS_TASK_NUM", 0)) if 'CRS_TASK_NUM' in os.environ else None

        label_selector = f'app!={self.app}'
        if num_concurrent_tasks is None or my_task is None:
            l.warning("⚠️⚠️⚠️ Environment variables NUM_CONCURRENT_TASKS or CRS_TASK_NUM not set!!! Defaulting to grabbing all pods again.")
        else:
            assert my_task >= 0, "CRS_TASK_NUM must be >= 0"
            for i in range(num_concurrent_tasks):
                if i == my_task - 1:
                    continue

                label_selector += f',support.shellphish.net/task-pool!=task{i+1}'
        pods = await self.list_pods_by_label(label_selector)

        pods_on_nodes = dict()

        for pod in pods:
            pod_name = pod.metadata.name
            node = pod.spec.node_name
            if node not in pods_on_nodes:
                pods_on_nodes[node] = dict(
                    tasks=[],
                    other=[]
                )
            if not pod.metadata or not pod.metadata.labels:
                l.warning(f"⚠️⚠️⚠️ Pod {pod_name} has no metadata or labels!")
                continue
            if pod.metadata.labels.get("app") == self.app or pod.metadata.labels.get("app") == self.app + "-set":
                pods_on_nodes[node]["tasks"].append(pod)
            else:
                pods_on_nodes[node]["other"].append(pod)

        # TODO record which tasks+jobs are on which nodes...

        # TODO(finaldeploy)
        # TODO update this with the correct node values
        # For now we are hard coding in the max number of nodes we have budgeted for for each pool
        # This will be used to know when we can no longer autoscale
        MAX_NODES_BY_POOL = {
            'fuzzing': int(os.environ.get("MAX_FUZZER_NODES",0)) or 25,
            'user': int(os.environ.get("MAX_USER_NODES",0)) or 80,
        } 

        # TODO(finaldeploy)
        # TODO Update this with the correct number of concurrent task pools
        NUM_TASK_POOLS = int(os.environ.get("NUM_TASK_POOLS",0)) or 8
        for i in range(NUM_TASK_POOLS):
            MAX_NODES_BY_POOL[f'fuzzing_task{i+1}'] = int(os.environ.get("MAX_FUZZER_NODES",0)) or 25

        # We need to know how many nodes are in each pool so that we can know if we hit the cap
        NODE_POOL_ENTRIES = dict()
        for node, host_node in zip(nodes, node_hosts):
            pool_type = host_node.labels.get("support.shellphish.net/pool", None)
            if host_node.labels.get("support.shellphish.net/task-pool"):
                pool_type += '_' + host_node.labels.get("support.shellphish.net/task-pool")


            if pool_type in MAX_NODES_BY_POOL:
                NODE_POOL_ENTRIES[pool_type] = NODE_POOL_ENTRIES.get(pool_type, [])
                NODE_POOL_ENTRIES[pool_type].append(host_node)

        for node, host_node in zip(nodes, node_hosts):
            node_name = host_node.name

            pool_type = host_node.labels.get("support.shellphish.net/pool", None)
            if host_node.labels.get("support.shellphish.net/task-pool"):
                pool_type += '_' + host_node.labels.get("support.shellphish.net/task-pool")


            pods = pods_on_nodes.get(node_name, {})

            external_quota_use = Quota.parse(0,0)

            other_pods = pods.get("other", [])
            for other_pod in other_pods:
                pod_name = other_pod.metadata.name
                for container in other_pod.spec.containers:
                    if container.resources and container.resources.requests:
                        #l.debug(f"POD {pod_name} @ {node_name} : {container.resources.requests}")
                        external_quota_use += Quota.parse(
                            container.resources.requests.get('cpu', 1),
                            container.resources.requests.get('memory', '1Gi')
                        )


            quota = Quota.parse(
                host_node.allocatable['cpu'],
                host_node.allocatable['memory']
            )

            # Add a 2% of the node's allocatable for overage
            overage = quota * 0.02

            external_quota_use += overage


            #l.debug(f"⚙️ Node {node_name} has {quota} allocatable with {external_quota_use} in use already by untracked pods")


            can_autoscale = True

            # Check if we have hit the cap on the number of nodes
            # in this specific pool. If so, then we will set can_autoscale to False
            # This will prevent PDT from overprovisioning further in the pool
            if (
                pool_type and
                MAX_NODES_BY_POOL.get(pool_type) and
                pool_type in NODE_POOL_ENTRIES
            ):
                num_in_pool = len(NODE_POOL_ENTRIES[pool_type])
                if num_in_pool >= MAX_NODES_BY_POOL.get(pool_type):
                    can_autoscale = False
                    l.warning(f"⚠️⚖️ Reached maximum node limit ({MAX_NODES_BY_POOL.get(pool_type)}) for pool '{pool_type}'. Disabling autoscaling.")
                    

            node_quota = NodeQuota(
                name=node_name,
                quota=quota,
                pre_allocated=external_quota_use,
                labels=host_node.labels,
                taints=host_node.taints,
                can_autoscale=can_autoscale,
            )

            nodes_with_quota.append((
                host_node,
                node_quota,
            ))

            if smallest_node_quota is None:
                smallest_node_quota = quota
            else:
                smallest_node_quota = Quota(min(smallest_node_quota.cpu, quota.cpu), min(smallest_node_quota.mem, quota.mem))

        # TODO load these from configuration instead

        # Find all nodes with like labels and taints and merge them into a single quota pools
        quota_pools = QuotaPoolSet.merge_nodes([
            node_quota
            for _, node_quota in nodes_with_quota
        ])

        fuzzing_pools = quota_pools.get_pools_with_label("support.shellphish.net/pool", "fuzzing")
        # Libfuzzer specific fuzzing nodes
        fuzzing_pools_lf = quota_pools.get_pools_with_label("support.shellphish.net/pool", "fuzzing-lf")

        # We need to iterate all the task pools and if any are not up, we create a stand in

        if not fuzzing_pools:
            fuzzing_pools = []


        for i in range(NUM_TASK_POOLS):
            task_pool_name = f"task{i+1}"
            matching_pool = next((pool for pool in fuzzing_pools if pool.labels.get("support.shellphish.net/task-pool") == task_pool_name), None)
            if not matching_pool:
                quota_pools.add_pool(QuotaPool(
                    nodes=[NodeQuota(
                        name=f'future-scaleable-node-fuzz-{task_pool_name}',
                        quota=Quota.parse(32,'64Gi'),
                        can_autoscale = True
                    )],
                    total_quota=Quota.parse(32,'64Gi'),
                    labels={
                        "support.shellphish.net/pool": "fuzzing",
                        "support.shellphish.net/allow-fuzzing": "true",
                        "support.shellphish.net/task-pool": task_pool_name,
                    },
                    taints={
                        "support.shellphish.net/only-fuzzing": "true",
                    },
                    can_autoscale=True,
                ))

            # Libfuzzer specific fuzzing nodes
            matching_pool = next((pool for pool in fuzzing_pools_lf if pool.labels.get("support.shellphish.net/task-pool") == task_pool_name), None)
            if not matching_pool:
                quota_pools.add_pool(QuotaPool(
                    nodes=[NodeQuota(
                        name=f'future-scaleable-node-fuzz-lf-{task_pool_name}',
                        quota=Quota.parse(32,'64Gi'),
                        can_autoscale = True
                    )],
                    total_quota=Quota.parse(32,'64Gi'),
                    labels={
                        "support.shellphish.net/pool": "fuzzing-lf",
                        "support.shellphish.net/allow-fuzzing-lf": "true",
                        "support.shellphish.net/task-pool": task_pool_name,
                    },
                    taints={
                        "support.shellphish.net/only-fuzzing-lf": "true",
                    },
                    can_autoscale=True,
                ))

        coverage_pool = quota_pools.get_pools_with_label("support.shellphish.net/pool", "coverage")
        if not coverage_pool or len(coverage_pool) == 0:
            quota_pools.add_pool(QuotaPool(
                nodes=[NodeQuota(
                    name='future-scaleable-node-cov',
                    quota=Quota.parse(16,'32Gi'),
                    can_autoscale = True
                )],
                total_quota=Quota.parse(16,'32Gi'),
                labels={
                    "support.shellphish.net/pool": "coverage",
                    "support.shellphish.net/allow-coverage": "true",
                },
                taints={
                    "support.shellphish.net/only-coverage": "true",
                },
                can_autoscale=True,
            ))
        patching_pool = quota_pools.get_pools_with_label("support.shellphish.net/pool", "patching")
        if not patching_pool or len(patching_pool) == 0:
            quota_pools.add_pool(QuotaPool(
                nodes=[NodeQuota(
                    name='future-scaleable-node-patch',
                    quota=Quota.parse(16,'32Gi'),
                    can_autoscale = True
                )],
                total_quota=Quota.parse(16,'32Gi'),
                labels={
                    "support.shellphish.net/pool": "patching",
                    "support.shellphish.net/allow-patching": "true",
                },
                taints={
                    "support.shellphish.net/only-patching": "true",
                },
                can_autoscale=True,
            ))
        gpu_pool = quota_pools.get_pools_with_label("support.shellphish.net/pool", "gpu")
        if not gpu_pool or len(gpu_pool) == 0:
            quota_pools.add_pool(QuotaPool(
                nodes=[NodeQuota(
                    name='future-scaleable-node-gpu',
                    quota=Quota.parse(16,'32Gi'),
                    can_autoscale = True
                )],
                total_quota=Quota.parse(16,'32Gi'),
                labels={
                    "support.shellphish.net/pool": "gpu",
                    "support.shellphish.net/only-gpu": "true",
                },
                taints={
                    "support.shellphish.net/only-gpu": "true",
                },
                can_autoscale=True,
            ))

        self._quota_pools = quota_pools

        total_quota = self.quota_pools.total_quota

        # XXX This is because the quota obj is used as a key in a dict right now in pipeline.py
        # Is this actually needed?
        self.quota.cpu = total_quota.cpu
        self.quota.mem = total_quota.mem
        if smallest_node_quota is not None:
            self.single_node_quota = smallest_node_quota

    def _id_to_name(self, task: str, job: str, replica: int) -> str:
        task = task.replace("_", "-")
        return f"{self.app}-{task}-{job}-{replica}"

    def _name_to_id(self, name: str, task: str) -> Tuple[str, int]:
        task = task.replace("_", "-")
        prefix = f"{self.app}-{task}-"
        if name.startswith(prefix):
            job, replica = name[len(prefix) :].split("-")
            return job, int(replica)
        raise Exception("Not a pod for this task")

    async def launch(self, task: str, job: str, replica: int, manifest):
        """Create a pod with the given manifest, named and labeled for this podman's app and the given job and
        task."""
        assert manifest["kind"] == "Pod"

        manifest["metadata"] = manifest.get("metadata", {})
        existing_labels = manifest["metadata"].get("labels", {})
        existing_labels.update(
            manifest
            .get('spec', {})
            .get('metadata', {})
            .get('labels', {})
        )
        existing_labels.update({
            "app": self.app,
            "task": task,
            "job": job,
            "replica": str(replica),
        })

        if replica != 0:
            existing_labels["preemptable"] = "true"
            # Add an annotation for safe eviction by cluster autoscaler
            manifest["metadata"]["annotations"] = manifest["metadata"].get("annotations", {})
            manifest["metadata"]["annotations"]["cluster-autoscaler.kubernetes.io/safe-to-evict"] = "true"

        manifest["metadata"].update(
            {
                "name": self._id_to_name(task, job, replica),
                "labels": existing_labels,
            }
        )

        for n in range(10):
            try:
                await self._create_namespaced_pod(manifest)
                break
            except ApiException as e:
                l.error(f"Failed to create pod: {e}")
                await asyncio.sleep(10)
        else:
            raise Exception("Failed to create pod")

    async def kill(self, task: str, job: str, replica: int | None):
        """Killllllllllllll."""
        pods = await self.query(task, job, replica)
        for pod in pods:
            try:
                await self._delete_namespaced_pod(pod.name)
            except ApiException:
                pass

    async def update(
        self, task: str, timeout: Optional[timedelta] = None
    ) -> Tuple[Dict[Tuple[str, int], datetime], Dict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]]]:
        """Do maintainence."""
        pods = await self.query(task=task)
        podmap = {pod.metadata.name: pod for pod in pods}
        dead = {name for name, pod in podmap.items() if pod.status.phase in ("Succeeded", "Failed")}
        live = set(podmap) - dead
        now = datetime.now(tz=timezone.utc)
        timed = {
            name for name in live if timeout is not None and podmap[name].metadata.creation_timestamp + timeout > now
        }
        live -= timed
        dead |= timed
        live_jobs = {self._name_to_id(name, task)[0] for name in live}

        def gen_done(pod):
            return {
                "reason": "Timeout" if pod.metadata.name in timed else pod.status.phase,
                "start_time": pod.metadata.creation_timestamp,
                "end_time": datetime.now(tz=timezone.utc),
                "image": pod.status.container_statuses[0].image,
                "node": pod.spec.node_name,
                "timeout": pod.metadata.name in timed,
                "success": pod.status.phase == "Succeeded",
            }

        async def io_guy(name) -> Optional[bytes]:
            try:
                return await self.logs(podmap[name])
            except (TimeoutError, ApiException, Exception):
                return None

        logs = await asyncio.gather(
            *(io_guy(name) for name in dead if self._name_to_id(name, task)[0] not in live_jobs)
        )
        await asyncio.gather(
            *(self._delete_namespaced_pod(name) for name in dead), return_exceptions=True
        )

        live_result = {
            (str(podmap[name].metadata.labels["job"]), int(podmap[name].metadata.labels["replica"])): podmap[
                name
            ].metadata.creation_timestamp
            for name in live
        }
        reap_result: DefaultDict[str, Dict[int, Tuple[Optional[bytes], Dict[str, Any]]]] = defaultdict(dict)
        for name, log in zip(dead, logs):
            job, replica = self._name_to_id(name, task)
            if job not in live_jobs:
                reap_result[job][replica] = (log, gen_done(podmap[name]))

        return live_result, dict(reap_result)

    # === Wrappers around kubernetes API calls ===

    async def _retry_api_call(
        self,
        func: Callable[[], Awaitable[Any]],
        *args,
        max_retries: int = 10,
        retry_delay: int = 10,
        return_none_on_404: bool = False,
        retry_404: bool = False,
        **kwargs,
    ):
        last_error = None
        for n in range(max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except ApiException as e:
                # Don't retry on 404 errors as they indicate a resource doesn't exist
                if (not retry_404 or return_none_on_404) and e.status == 404:
                    l.warning(f"Received 404 error while calling {func.__name__} ({type(e)} {e})")
                    if return_none_on_404:
                        return None
                    raise e

                l.warning(f"Failed to call API {func.__name__}, retrying in {retry_delay} seconds ({n+1}/{max_retries}) ({type(e)} {e})")
                last_error = e
                if n >= max_retries - 1:
                    raise last_error
                await asyncio.sleep(retry_delay)
            except (
                aiohttp.client_exceptions.ClientConnectorError,
                asyncio.exceptions.TimeoutError,
            ) as e:
                l.warning(f"Failed to call API, retrying in {retry_delay} seconds ({n+1}/{max_retries}) ({type(e)} {e})")
                last_error = e
                if n >= max_retries - 1:
                    raise last_error
                await asyncio.sleep(retry_delay)
        raise last_error

    async def _list_nodes(self, label_selector: str, max_retries: int = 10) -> List[Any]:
        return (await self._retry_api_call(
            self.v1.list_node,
            label_selector=label_selector,
            max_retries=max_retries,
            retry_delay=10,
        )).items

    async def _create_namespaced_pod(self, manifest: Dict[str, Any], max_retries: int = 10):
        return await self._retry_api_call(
            self.v1.create_namespaced_pod,
            self.namespace,
            manifest,
            max_retries=max_retries,
            retry_delay=10,
        )

    async def _delete_namespaced_pod(self, name: str, max_retries: int = 10):
        return await self._retry_api_call(
            self.v1.delete_namespaced_pod,
            name,
            self.namespace,
            max_retries=max_retries,
            retry_delay=10,
            return_none_on_404=True,
        )

    async def _create_namespaced_daemon_set(self, manifest: Dict[str, Any], max_retries: int = 10):
        return await self._retry_api_call(
            self.v1apps.create_namespaced_daemon_set,
            self.namespace,
            manifest,
            max_retries=max_retries,
            retry_delay=10,
        )
    async def _delete_namespaced_daemon_set(self, name: str, max_retries: int = 10):
        return await self._retry_api_call(
            self.v1apps.delete_namespaced_daemon_set,
            name,
            self.namespace,
            max_retries=max_retries,
            retry_delay=10,
            return_none_on_404=True,
        )

    async def _list_namespaced_daemonsets(self, label_selector: str, max_retries: int = 10) -> List[Any]:
        return (await self._retry_api_call(
            self.v1apps.list_namespaced_daemon_set,
            self.namespace,
            label_selector=label_selector,
            max_retries=max_retries,
            retry_delay=10,
        )).items

    async def _read_namespaced_pod_log(self, name, timeout=10, max_retries = 5, preload_content=True, return_none_on_404=False, container=None):
        return await self._retry_api_call(
            self.v1.read_namespaced_pod_log,
            name,
            self.namespace,
            _request_timeout=timeout,
            max_retries=max_retries,
            retry_delay=10,
            _preload_content=preload_content,
            return_none_on_404=return_none_on_404,
            container=container,
        )

    async def _list_namespaced_pods(self, label_selector: str, max_retries: int = 10) -> List[Any]:
        return (await self._retry_api_call(
            self.v1.list_namespaced_pod,
            self.namespace,
            label_selector=label_selector,
            max_retries=max_retries,
            retry_delay=10,
        )).items

    async def list_pods_by_label(self, label_selector: str) -> List[Any]:
        async with self._lock:

            should_use_pod_cache = self.pod_cache_enabled
            now = time.time()
            if (
                self.pod_cache_last_updated is not None
                and self.pod_cache_ttl is not None
            ):
                if now - self.pod_cache_last_updated > self.pod_cache_ttl:
                    should_use_pod_cache = False

            # WARN: This function may race with the cache clearing, so we need to atomically update self._cached_pods
            cached_pods = {}
            if should_use_pod_cache:
                cached_pods = self._cached_pods
            if cached_pods is None:
                cached_pods = {}
            if label_selector not in cached_pods:
                cached_pods[label_selector] = await self._list_namespaced_pods(label_selector)

            if should_use_pod_cache:
                self._cached_pods = cached_pods
                self.pod_cache_last_updated = now

        return cached_pods[label_selector]

    async def query(self, job=None, task=None, replica=None) -> List[Any]:
        """Return a list of pods labeled for this podman's app and (optional) the given job and task."""

        pods = await self.list_pods_by_label(f"app={self.app}")

        assert pods is not None
        return [
            pod
            for pod in pods
            if (job is None or pod.metadata.labels["job"] == job)
            and (task is None or pod.metadata.labels["task"] == task)
            and (replica is None or pod.metadata.labels["replica"] == str(replica))
        ]

    async def delete(self, pod: Any):
        """Destroy the given pod."""
        try:
            await self._delete_namespaced_pod(pod.metadata.name)
        except ApiException:
            pass

    async def logs(self, pod: Any, timeout=30, max_retries=0) -> bytes:
        all_logs = b''
        init_containers = None

        # First we see if there are any init containers
        if pod.spec.init_containers:
            init_containers = [container.name for container in pod.spec.init_containers]

        if init_containers:
            for container in init_containers:
                try:
                    all_logs += f'=== Init container {container} ===\n\n'.encode()
                    logs = await self._read_namespaced_pod_log(
                        pod.metadata.name,
                        timeout=timeout,
                        max_retries=max_retries,
                        preload_content=False,
                        return_none_on_404=True,
                        container=container,
                    )
                    if logs is None:
                        all_logs += f'Failed to retrieve logs: 404 Not Found for pod {pod.metadata.name}\n\n\n'.encode()
                    else:
                        all_logs += await logs.read()
                        all_logs += b'\n\n\n'
                except Exception as e:
                    all_logs += f'Failed to retrieve logs: {e}\n\n\n'.encode()
            
            all_logs += f'=== Main container ===\n\n'.encode()

        try:
            """Retrieve the logs for the given pod."""
            response = await self._read_namespaced_pod_log(
                pod.metadata.name,
                timeout=timeout,
                max_retries=max_retries,
                preload_content=False,
                return_none_on_404=True,
            )
            if response is None:
                all_logs += f'Failed to retrieve logs: 404 Not Found for pod {pod.metadata.name}\n'.encode()
            else:
                all_logs += await response.read()
        except Exception as e:
            all_logs += f'Failed to retrieve logs: {e}\n\n\n'.encode()
        
        return all_logs
