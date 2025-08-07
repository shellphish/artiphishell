"""This module houses the executors.

An executor is an interface that allows executing various classes of runnables. The generic executor interface doesn't
actually allow this, but instead allows you to attempt to upcast your executor into a type which provides a specific
runnable type (containers, processes, or kubernetes pods), which may fail.

This level of abstraction allows Tasks to be unconcerned by which executor they are passed, which allows Task to be a
class focused on what is run instead of how it is run.
"""

from typing import TYPE_CHECKING

from pydatatask.host import Host
from pydatatask.quota import Quota

if TYPE_CHECKING:
    from ..pipeline import Pipeline
    from . import container_manager, container_set_manager, pod_manager, proc_manager


class Executor:
    """The executor base class.

    Provides nothing other than the ability to upcast to other executor types and a quota.
    """

    def __init__(self, quota: Quota):
        self.quota = quota

    def to_process_manager(self) -> "proc_manager.AbstractProcessManager":
        """Convert this executor into one that will run processes on the same machine.

        This is allowed to fail with TypeError if this is not possible.
        """
        raise TypeError(f"{type(self)} cannot host a bare process")

    def to_pod_manager(self) -> "pod_manager.PodManager":
        """Convert this executor into one that will run kubernetes pods on the same machine.

        This is allowed to fail with TypeError if this is not possible.
        """
        raise TypeError(f"{type(self)} cannot host a kubernetes pod")

    def to_container_manager(self) -> "container_manager.AbstractContainerManager":
        """Convert this executor into one that will run containers on the same machine.

        This is allowed to fail with TypeError if this is not possible.
        """
        raise TypeError(f"{type(self)} cannot host a linux container")

    def to_container_set_manager(self) -> "container_set_manager.AbstractContainerSetManager":
        raise TypeError(f"{type(self)} cannot host a linux container set")

    @property
    def host(self) -> Host:
        """The host that this executor's tasks will run on."""
        raise NotImplementedError

    async def launch_agent(self, pipeline: "Pipeline") -> None:
        """Spawn the pydatatask http agent using this executor."""
        raise TypeError("Not supported, yikes")

    async def teardown_agent(self) -> None:
        """Kill the pydatatask http agent that was spawned using this executor."""
        raise TypeError("Not supported, yikes")

    def cache_flush(self) -> None:
        """Flush any cached data."""
        pass
