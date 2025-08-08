"""Pydatatask defines the notion of resources, or numerical quantities of CPU and memory which can be allocated to a
given job. This is mediated through a :class:`QuotaManager`, an object which can atomically track increments and
decrements from a quota, and reject a request if it would break the quota.

Typical usage is to construct a :class:`QuotaManager` and pass it to a task constructor:

.. code:: python

    quota = pydatatask.QuotaManager(pydatatask.Quota.parse(cpu='1000m', mem='1Gi'))
    task = pydatatask.ProcessTask("my_task", localhost, quota, ...)

TODO REWRITE THIS GODDAMN
"""

from __future__ import annotations

import logging
import os
import json

l = logging.getLogger(__name__)

from typing import TYPE_CHECKING, Optional, Union, Dict, List, Set, Any, Tuple
from importlib_metadata import entry_points
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum, auto

from kubernetes.utils import parse_quantity
from typing_extensions import Self
import psutil

from pydatatask.host import KubeHostNode

if TYPE_CHECKING:
    from pydatatask.executor.base import Executor
    from pydatatask.task import Task



__all__ = ("QuotaType", "Quota", "parse_quantity", "_MaxQuotaType", "_TemplateQuotaType", "MAX_QUOTA")


class QuotaType(Enum):
    """An enum class indicating a type of resource.

    Presently can be CPU or MEM.
    """

    CPU = auto()
    MEM = auto()


@dataclass(eq=False)
class Quota:
    """A dataclass containing a quantity of resources.

    Quotas can be summed:

    .. code:: python

        r = pydatatask.Quota.parse(1, 1)
        r += pydatatask.Quota.parse(2, 3)
        r -= pydatatask.Quota.parse(1, 1)
        assert r == pydatatask.Quota.parse(2, 3)
    """

    cpu: Decimal = field(default=Decimal(0))
    mem: Decimal = field(default=Decimal(0))

    @classmethod
    def parse(
        cls,
        cpu: Union[str, float, int, Decimal],
        mem: Union[str, float, int, Decimal],
    ) -> Self:
        """Construct a :class:`Quota` instance by parsing the given quantities of CPU and memory."""
        return cls(cpu=parse_quantity(cpu), mem=parse_quantity(mem))

    def __add__(self, other: Self):
        return type(self)(cpu=self.cpu + other.cpu, mem=self.mem + other.mem)

    def __mul__(self, other: Union[int, float, Decimal]):
        other_d = Decimal(other)
        return type(self)(cpu=self.cpu * other_d, mem=self.mem * other_d)

    def __sub__(self, other: Self):
        return self + other * -1

    def excess(self, limit: Self) -> Optional[QuotaType]:
        """Determine if these resources are over a given limit.

        :return: The QuotaType of the first resource that is over-limit, or None if self is under-limit.
        """
        if self.cpu > limit.cpu:
            return QuotaType.CPU
        elif self.mem > limit.mem:
            return QuotaType.MEM
        else:
            return None


LOCALHOST_QUOTA = Quota.parse(cpu=psutil.cpu_count(), mem=psutil.virtual_memory().total)


class _MaxQuotaType(float):
    pass

class _TemplateQuotaType(str):
    pass

MAX_QUOTA = _MaxQuotaType(1.0)

@dataclass(eq=False)
class NodeQuota:
    """
    A quota for a specific node, including metadata about the node.
    """
    name: str
    quota: Quota
    labels: Optional[Dict[str, str]] = None
    taints: Optional[Dict[str, str]] = None

    pre_allocated: Optional[Quota] = None
    can_autoscale: bool = False
    """
    This is the amount of space already allocated to pods not tracked by pydatatask
    """

    def can_launch(self, request_quota: Quota) -> bool:
        """
        Determine if a request quota can be launched on this node.
        """
        return request_quota.excess(self.quota) is None

    @classmethod
    def get_localhost_quota(cls):
        return cls(
            name="localhost",
            quota=LOCALHOST_QUOTA,
            labels={"pydatatask/single-node": "true"},
            taints={},
        )




@dataclass(eq=False)
class QuotaPool:
    """
    A pool of nodes with a common set of labels and taints
    """
    nodes: List[NodeQuota]
    total_quota: Quota
    labels: Dict[str, str]
    taints: Dict[str, str]

    used_quota: Quota = field(default_factory=Quota)
    can_autoscale: bool = False

    def __str__(self):
        names = [node.name for node in self.nodes]
        names = ", ".join(names)
        labels = ", ".join([f"{k}={v}" for k, v in self.labels.items()]) if self.labels else "None"
        taints = ", ".join([f"{k}={v}" for k, v in self.taints.items()]) if self.taints else "None"
        return f"QuotaPool([{names}], labels={labels}, taints={taints})"

    def __repr__(self):
        return str(self)

    def get_name(self) -> str:
        try:
            name = self.labels.get("support.shellphish.net/pool", "unknown")
            if self.labels.get("support.shellphish.net/task-pool"):
                name += '_' + self.labels.get("support.shellphish.net/task-pool")
        except Exception as e:
            name = "unknown"
        return name

    def get_number_of_nodes(self) -> int:
        return len(self.nodes)

    def get_quota_per_node(self) -> Quota:
        smallest_quota = None
        for node in self.nodes:
            if smallest_quota is None or not self.total_quota.excess(smallest_quota):
                smallest_quota = node.quota

        return smallest_quota or Quota.parse(0,0)

    def __init__(self, nodes: List[NodeQuota], total_quota: Quota, labels: Dict[str, str] | None = None, taints: Dict[str, str] | None = None, can_autoscale: bool = False):
        self.nodes = nodes
        self.total_quota = total_quota or Quota.parse(0,0)
        self.labels = labels or {}
        self.taints = taints or {}
        self.can_autoscale = can_autoscale

    @property
    def single_node_resource_limit(self) -> Quota:
        return self.get_quota_per_node()

    @classmethod
    def get_localhost_quota(cls) -> "QuotaPool":
        return QuotaPool(
            nodes=[NodeQuota(
                name="localhost",
                quota=LOCALHOST_QUOTA,
                labels={"pydatatask/single-node": "true"},
                taints={},
            )],
            total_quota=LOCALHOST_QUOTA,
            labels={"pydatatask/single-node": "true"},
            taints={},
        )

    @classmethod
    async def get_quota_pools_for_task_manager(cls, task_manager: Executor) -> "QuotaPoolSet":
        if task_manager is None:
            l.warning("⚠️ No task manager to get quota pools for")
            return QuotaPoolSet([])

        if not hasattr(task_manager, 'quota_pools'):
            l.warning(f"⚠️ Task manager {task_manager} does not have quota pools property")
            return QuotaPoolSet([])

        return task_manager.quota_pools

    @classmethod
    async def get_quota_pools_for_tasks(cls, tasks: Dict[str, Any]) -> "QuotaPoolSet":
        "We just need to grab a ref to the underlying manager from any task we can"
        if len(tasks) == 0:
            l.warning("⚠️ No tasks to get quota pools for")
            return QuotaPoolSet([])

        for name, task in tasks.items():
            # Just grab the quota pools for the first task we can
            # TODO Do this a better way...
            return await cls.get_quota_pools_for_task_manager(task.manager)

        return QuotaPoolSet([])

    @classmethod
    async def calculate_usage(
        cls,
        pipeline: Any,
        live_jobs: Dict[str, Set[str]],
    ) -> "QuotaPoolSet":
        """
        Calculate the usage of each quota pool.
        """

        tasks = pipeline.tasks

        if len(tasks) == 0:
            return QuotaPoolSet([])

        quota_pools = await cls.get_quota_pools_for_tasks(tasks)

        if len(quota_pools) == 0:
            l.warning("⚠️ No quota pools to calculate usage")
            return QuotaPoolSet([])

        #l.debug("\n====== Calculating Usage ======")

        # Each job charges its quota to a specific pool
        # We sum up the quota for each pool

        for pool in quota_pools.quota_pools:
            pool.used_quota = Quota.parse(0,0)
            for node in pool.nodes:
                if node.pre_allocated:
                    #l.debug(f"💧 Node {node.name} has {node.pre_allocated} pre-allocated (non-pydatatask pods)")
                    pool.used_quota += node.pre_allocated

        for task_name in live_jobs.keys():
            task = tasks[task_name]
            for job in live_jobs[task_name]:
                # For each existing job
                # Get the pool it was assigned to
                pool = await quota_pools.get_pool_for_job(pipeline, task, job)

                #number_of_nodes = pool.get_number_of_nodes()

                # get the quota it is requesting for this pool (these are all replica 0s)
                task_usage = await task.get_quota_for_job(job, replica=0, pool=pool)

                if not pool.used_quota:
                    pool.used_quota = Quota.parse(0,0)

                # Turns out daemonsets already are multipled by the number of nodes they are running on so...
                # So we do not not need to modify the quota returned by the task.get_quota_for_job(...)

                # Add it to the pool's used quota
                pool.used_quota += task_usage
                #l.debug(f"$ {task_name} Charging {task_usage} to pool {pool} for {task_name}:{job} -> {pool.used_quota}")

        #l.debug("============================\n")
        return quota_pools

    def release_reservation(self, reservation: "QuotaReservation"):
        """
        Release a reservation.
        """
        if self.used_quota is None:
            raise ValueError("No reservation to release")

        self.used_quota -= reservation.quota

    def can_launch(self, request_quota: Quota, autoscale: bool = False) -> Tuple[bool, Optional[QuotaType]]:
        """
        Determine if a request quota can be launched on this node.
        """
        new_amt = self.used_quota + request_quota

        total_amt = self.total_quota

        if autoscale and self.can_autoscale:
            # If we allow autoscaling, we need to actually OVER-estimate the quota
            # that way we can schedule new pods (which will be pending...) to
            # trigger the actual autoscaling
            # TODO XXX This should be capped at a max number of nodes we can launch
            #     to prevent us from over-provisioning when we can't scale
            node_size = self.get_quota_per_node()
            total_amt  = total_amt + node_size
            #l.debug(f"🔍 Autoscaling enabled, over-provisioning quota by {request_quota} + {node_size}")

        #l.debug(f"🔍 Total quota allocatable: {total_amt}")

        excess = new_amt.excess(total_amt)

        if not excess and new_amt.excess(self.total_quota):
            cpu_o = int(total_amt.cpu)
            cpu_t = int(self.total_quota.cpu)
            mem_o = int(total_amt.mem / (1024 * 1024 * 1024))
            mem_t = int(self.total_quota.mem / (1024 * 1024 * 1024))
            l.info(f"⚖️ Over-provisioning quota to trigger autoscaling: {cpu_o}/{cpu_t} CPU {mem_o}/{mem_t}GB MEM in pool {self.get_name()}")

        return excess is None, excess

    async def try_reserve(
        self,
        quota: Optional[Quota]=None,
        task: Optional[Task]=None,
        job: Optional[str]=None,
        replica: Optional[int]=None,
    ) -> Tuple[QuotaReservation | None, Optional[Quota], Optional[Any]]:
        """
        Try to reserve a quota.
        """
        if self.used_quota is None:
            self.used_quota = Quota.parse(0,0)

        if quota is not None:
            r_quota = quota
        else:
            if task is None:
                raise ValueError("No task to get quota for")
            if job is None:
                r_quota = task.job_quota
            else:
                r_quota = await task.get_quota_for_job(job, replica=replica, pool=self)
                if r_quota is None:
                    raise TypeError(f"You can't get the quota for a {type(task)}")

        if self.taints and task is not None:
            if not task.node_taints:
                return None, r_quota, 'taint_mismatch'
            for taint, value in self.taints.items():
                if task.node_taints.get(taint) != value:
                    return None, r_quota, 'taint_mismatch'

        #l.debug(f"🔍📦 Checking if we can allocate {r_quota} on {self} with {self.used_quota} used / {self.total_quota} total")
        
        can_launch, excess = self.can_launch(
            r_quota,
            autoscale=self.can_autoscale,
        )
        if can_launch:
            self.used_quota += r_quota
            selectors = {}
            tolerances = {}
            if task and task.node_labels:
                selectors.update({
                    k: v for k, v in task.node_labels.items()
                    if not k.startswith("meta.support.shellphish.net/")
                })
            if task and task.replica_node_labels and replica is not None and replica > 0:
                selectors.update(task.replica_node_labels)

            if task and task.node_taints:
                tolerances.update(task.node_taints)
            if task and task.replica_node_taints and replica is not None and replica > 0:
                tolerances.update(task.replica_node_taints)

            for label, value in self.labels.items():
                if label.startswith('support.shellphish.net/pool'):
                    selectors[label] = value
                    continue
                if label.startswith('support.shellphish.net/task-pool'):
                    selectors[label] = value
                    continue

            res = QuotaReservation(
                pool=self,
                quota=r_quota,
                selectors_to_apply=selectors,
                tolerances_to_apply=tolerances,
            )
            return res, r_quota, None
        else:
            return None, r_quota, excess

    @property
    def node_count(self) -> int:
        return len(self.nodes)

from functools import lru_cache

@lru_cache(maxsize=None)
def get_node_labels_function(function_name: str):
    try:
        eps = entry_points(group=f"pydatatask.node_labels_functions")
        ep = eps[function_name]  # newer api, or use eps.get(function_name)
        return ep.load()
    except Exception as e:
        l.error(f"⚠️⚠️⚠️ Node labels function pydatatask.node_labels_functions.{function_name} not found! {e}")
        return None

async def get_extra_node_labels(pipeline: Any, task: Any|str, job: str, replica: int = 0) -> Dict[str, str]:
    if isinstance(task, str):
        task_name = task
    else:
        task_name = task.name

    extra_node_labels = None
    node_labels_function = task.node_labels_function
    if node_labels_function is not None:
        fn = get_node_labels_function(node_labels_function)
        if fn:
            extra_node_labels = await fn(pipeline, task_name, job, replica)

    return extra_node_labels

@dataclass(eq=False)
class QuotaPoolSet:
    """
    A set of quota pools, each with a different node selector and taints
    """
    quota_pools: List[QuotaPool]

    def __init__(self, quota_pools: List[QuotaPool]):
        self.quota_pools = quota_pools

    @property
    def total_quota(self) -> Quota:
        total_quota = Quota.parse(0,0)
        for pool in self.quota_pools:
            total_quota += pool.total_quota
        return total_quota

    @classmethod
    def get_localhost_quota_pool(cls) -> "QuotaPoolSet":
        import traceback
        return QuotaPoolSet([QuotaPool.get_localhost_quota()])

    @classmethod
    def merge_nodes(cls, nodes: List["NodeQuota"]) -> "QuotaPoolSet":
        """
        Merge a list of quota pools into a single quota pool.
        """
        merged = {}
        for node in nodes:
            key = (
                tuple(sorted(
                    node.labels.items()
                    if node.labels else []
                )),
                tuple(sorted(
                    node.taints.items() 
                    if node.taints else []
                )),
                # Do not consider the can_autoscale flag as we are being conservative
            )
            key = json.dumps(key)
            if key not in merged:
                merged[key] = [node]
            else:
                merged[key].append(node)

        pools = []
        for key, merged_nodes in merged.items():
            quota_sum = Quota.parse(0,0)
            for node in merged_nodes:
                quota_sum += node.quota

            pools.append(QuotaPool(
                nodes=merged_nodes,
                total_quota=quota_sum,
                labels=merged_nodes[0].labels,
                taints=merged_nodes[0].taints,
                # We will only mark this pool as autoscaling if all the nodes in the pool are marked that way
                can_autoscale=all(
                    n.can_autoscale
                    for n in merged_nodes
                )
            ))

        return cls(quota_pools=pools)

    def get_pools_with_label(self, label: str, value: str) -> List[QuotaPool]:
        return [
            pool for pool in self.quota_pools
            if pool.labels.get(label) == value
        ]
    
    def add_pool(self, pool: QuotaPool):
        self.quota_pools.append(pool)

    def log(self):
        for i,pool in enumerate(self.quota_pools):
            name = ''
            if pool.labels:
                name = pool.labels.get("support.shellphish.net/pool")
            l.debug(f"━💧 Pool {name}")
            if pool.labels:
                for label, value in pool.labels.items():
                    if label.startswith('support.shellphish.net/pool'):
                        continue
                    l.debug(f"  ┃ 🏷️ {label}={value}")
            if pool.taints:
                for taint, value in pool.taints.items():
                    l.debug(f"  ┃ ⛔ Unless {taint}={value}")
            if pool.can_autoscale:
                l.debug(f"  ┃ ⚖️ Autoscaling Enabled")
            if pool.used_quota:
                cpu_p = int(float(pool.used_quota.cpu) / float(pool.total_quota.cpu) * 100)
                mem_p = int(float(pool.used_quota.mem) / float(pool.total_quota.mem) * 100)
                cpu_u = int(pool.used_quota.cpu)
                cpu_t = int(pool.total_quota.cpu)
                mem_u = int(pool.used_quota.mem / (1024 * 1024 * 1024))
                if mem_u < 10:
                    mem_u = int(pool.used_quota.mem / (1024 * 1024 * 1024) * 100) / 100
                    mem_u = f"{mem_u:0.2f}"
                mem_t = int(pool.total_quota.mem / (1024 * 1024 * 1024))

                l.debug(
                    f"  ┃ 📊 Used {cpu_u}/{cpu_t} [{cpu_p}%] CPU  " +
                    f"{mem_u}/{mem_t}GB [{mem_p}%] MEM (excluding replicas)"
                )
            for j, node in enumerate(pool.nodes):
                is_last = j == len(pool.nodes) - 1
                cpu_u = int(node.quota.cpu)
                mem_u = int(node.quota.mem / (1024 * 1024 * 1024))
                l.debug(f"  {'┗━' if is_last else '┣━'} 📦 Node {node.name} = {cpu_u} CPU {mem_u}GB MEM")

    async def get_matching_pools(self, pipeline: Optional[Any], task: Any|str, job=None, verbose=False) -> "QuotaPoolSet":
        if isinstance(task, str):
            if pipeline is None:
                raise ValueError(f"No pipeline to get task {task} from, pass pipeline or actual task object")
            task: Any = pipeline.tasks[task]

        if len(self.quota_pools) == 0:
            raise ValueError("No quota pools to get pool for")

        node_labels = {}
        if task and hasattr(task, 'node_labels') and task.node_labels:
            node_labels = task.node_labels.copy()

        is_single_node = False
        for pool in self.quota_pools:
            if os.environ.get("DISALLOW_SINGLE_NODE_MODE"):
                continue
            if pool.labels and pool.labels.get("pydatatask/single-node") == "true":
                is_single_node = True
                break

        # If we have a pipeline we can lookup extra node labels which might depend on pipeline state
        if (
            not is_single_node
            and pipeline
            and task
            and hasattr(task, 'node_labels_function')
            and task.node_labels_function
        ):
            extra_node_labels = await get_extra_node_labels(pipeline, task, job)
            if extra_node_labels:
                node_labels.update(extra_node_labels)

        if verbose:
            l.debug(f"🔍 Node labels: {node_labels}")

        possible_pools = []
        for pool in self.quota_pools:
            is_good = True
            is_single_node = False

            if pool.labels and pool.labels.get("pydatatask/single-node") == "true":
                # Just as a backup
                if not os.environ.get("DISALLOW_SINGLE_NODE_MODE"):
                    # In single-node mode we launch on any node we get
                    is_single_node = True
                    is_good = True

            # If provided with node_labels, only include pools that match
            if not is_single_node and node_labels:
                if verbose:
                    l.debug(f"🔍 Comparing node labels: {node_labels} to pool labels: {pool.labels}")
                for label, value in node_labels.items():
                    if label.startswith("meta.support.shellphish.net/"):
                        # meta labels are not part of node selection
                        continue
                    if verbose:
                        l.debug(f"     - {label}={value} in node selector")
                        l.debug(f"  vs - {label}={pool.labels.get(label)} in pool labels")


                    matching_pool_value = pool.labels.get(label)
                    if matching_pool_value is None:
                        is_good = False
                        if verbose:
                            l.debug(f"🚫 Pool {pool.labels} x {pool.taints} does not match node label {label}={value}")
                        break
                    if matching_pool_value != value:
                        is_good = False
                        if verbose:
                            l.debug(f"🚫 Pool {pool.labels} x {pool.taints} does not match node label {label}={value}")
                        break

            if not is_good:
                continue

            if not is_single_node and pool.taints:
                # Taints normally prevent scheduling, but if the task
                # has the same taint then it can be scheduled on here
                if not task or not hasattr(task, 'node_taints') or not task.node_taints:
                    continue

                for taint, value in pool.taints.items():
                    match = task.node_taints.get(taint)
                    if match is None:
                        is_good = False
                        if verbose:
                            l.debug(f"🚫 Pool {pool.labels} x {pool.taints} does not match node taint {taint}={value}")
                        break
                    if match != value:
                        is_good = False
                        if verbose:
                            l.debug(f"🚫 Pool {pool.labels} x {pool.taints} does not match node taint {taint}={value}")
                        break

            if not is_good:
                continue

            if verbose:
                l.debug(f"✅ Pool {pool.labels} x {pool.taints} matches node labels {node_labels}")

            possible_pools.append(pool)

        if len(possible_pools) == 0:
            return QuotaPoolSet([])
        
        affinity = {}

        # Sort by affinity
        # Nodes which match provided affinity tags will be higher ranking and the more matching tags the better 
        possible_pools.sort(key=lambda pool: len([
            (k,v) for k,v in pool.labels.items()
            if affinity.get(k) == v
        ]), reverse=True)

        return QuotaPoolSet(possible_pools)

    async def try_reserve(
        self,
        quota: Optional[Quota]=None,
        task: Any=None,
        job: Optional[str]=None,
        replica: Optional[int]=None,
    ) -> Tuple[QuotaReservation | None, Optional[Quota], Optional[Any]]:
        """
        Try to reserve a arbitrary quota or quota for a specific task/job.
        """
        excess = None
        r_quota = None

        # TODO XXX handle reservation of containersets
        # They should set `quota_per_instance` based on the original quota rather than the quota for the current job

        # TODO sort by priority to the task
        for pool in self.quota_pools:
            reservation, r_quota, excess = await pool.try_reserve(quota=quota, task=task, job=job, replica=replica)

            if reservation is not None:
                if task and task.node_affinity:
                    reservation.affinity_to_apply = task.node_affinity.copy()
                if task and task.pod_labels:
                    reservation.labels_to_apply = task.pod_labels.copy()
                return reservation, r_quota, None

        return None, r_quota, excess

    @classmethod
    async def get_pool_for_job_from_all_pools(cls, pipeline: Optional[Any], task: Any|str, job: str, multiple_ok: bool = False) -> QuotaPool|List[QuotaPool]:
        if isinstance(task, str):
            if pipeline is None:
                raise ValueError(f"No pipeline to get task {task} from, pass pipeline or actual task object")
            task: Any = pipeline.tasks[task]

        pools = task.manager.quota_pools
        if not pools:
            raise ValueError("No quota pools to get pool for")

        return await pools.get_pool_for_job(pipeline, task, job, multiple_ok=multiple_ok)

    async def get_pool_for_job(self, pipeline: Optional[Any], task: Any|str, job: str, multiple_ok: bool = False) -> QuotaPool|List[QuotaPool]:
        if len(self.quota_pools) == 0:
            raise ValueError("No quota pools to get pool for")

        if isinstance(task, str):
            if pipeline is None:
                raise ValueError(f"No pipeline to get task {task} from, pass pipeline or actual task object")
            task: Any = pipeline.tasks[task]

        matching_pools = await self.get_matching_pools(pipeline, task, job)
        if len(matching_pools.quota_pools) == 0:
            raise ValueError("No matching pools to get pool for")

        if multiple_ok:
            return matching_pools.quota_pools

        if len(matching_pools.quota_pools) > 1:
            l.warning(f"⚠️ Multiple matching pools for {task.name}:{job}, using first")

        return matching_pools.quota_pools[0]

    def __len__(self):
        return len(self.quota_pools)
    
    @property
    def node_count(self) -> int:
        return sum(pool.node_count for pool in self.quota_pools)

    def get_quota_per_node(self) -> Quota:
        smallest_quota = None
        for pool in self.quota_pools:
            if smallest_quota is None or not self.total_quota.excess(smallest_quota):
                smallest_quota = pool.get_quota_per_node()

        return smallest_quota or Quota.parse(0,0)

    @property
    def single_node_resource_limit(self) -> Quota:
        return self.get_quota_per_node()

    def has_autoscaling(self) -> bool:
        return any(pool.can_autoscale for pool in self.quota_pools)

@dataclass(eq=False)
class QuotaReservation:
    """
    A reservation for a specific quota pool.
    """
    pool: QuotaPool
    quota: Quota
    
    labels_to_apply: Optional[Dict[str, str]] = None
    selectors_to_apply: Optional[Dict[str, str]] = None
    tolerances_to_apply: Optional[Dict[str, str]] = None
    affinity_to_apply: Optional[Dict[str, str]] = None

    @property
    def quota_per_instance(self) -> Quota:
        return self.quota

    def release(self):
        """
        Release the reservation.
        """
        self.pool.release_reservation(self)

@dataclass(eq=False)
class ContainerSetQuotaReservation:
    """
    Used for containersets / daemonsets where they use a fixed
    amount on every node across one or more pools
    """
    pools: List[QuotaPool]
    quota_per_instance: Quota

@dataclass(eq=False)
class QuotaPoolSelector:
    """
    If we need to select which quota pool to launch a task into

    If you have multiple possible quotas, it will force it to choose one to spawn into
    """
    quota_pools: List[QuotaPool]
