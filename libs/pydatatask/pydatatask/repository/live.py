"""This module contains repositories for viewing the current state of a kubernetes cluster or other container runner
as a data store."""

from typing import TYPE_CHECKING, Any, List

from .base import Repository

if TYPE_CHECKING:
    from ..task import ContainerSetTask, ContainerTask, KubeTask, ProcessTask


class LiveKubeRepository(Repository):
    """A repository where keys translate to ``job`` labels on running kube pods.

    This repository is constructed automatically by a `KubeTask` or subclass and is linked as the ``live`` repository.
    Do not construct this class manually.
    """

    _EXCLUDE_BACKUP = True

    def __init__(self, task: "KubeTask"):
        super().__init__()
        self.task = task

    def footprint(self):
        return []

    def __getstate__(self):
        return (self.task.name,)

    async def unfiltered_iter(self):
        seen = set()
        for pod in await self.pods():
            job = str(pod.metadata.labels["job"])
            if job in seen:
                continue
            seen.add(job)
            yield job

    async def cache_key(self, job):
        return None

    async def contains(self, item, /):
        return bool(await self.task.podman.query(task=self.task.name, job=item))

    def __repr__(self):
        return f"<LiveKubeRepository task={self.task.name}>"

    async def pods(self) -> List[Any]:
        """A list of live pod objects corresponding to this repository."""
        return await self.task.podman.query(task=self.task.name)

    async def delete(self, job, /):
        """Deleting a job from this repository will delete the pods for that job."""
        await self.task.kill(job, None)


class LiveContainerRepository(Repository):
    """A repository where keys translate to containers running in a container executor.

    This repository is constructed automatically by a :class:`ContainerTask` or subclass and is linked as the ``live``
    repository. Do not construct this class manually.
    """

    _EXCLUDE_BACKUP = True

    def __init__(self, task: "ContainerTask"):
        super().__init__()
        self.task = task

    def footprint(self):
        return []

    def __getstate__(self):
        return (self.task.name,)

    async def unfiltered_iter(self):
        seen = set()
        for name, _ in await self.task.manager.live(self.task.name):
            if name in seen:
                continue
            seen.add(name)
            yield name

    async def contains(self, item, /):
        return any(item == job for job, _ in await self.task.manager.live(self.task.name))

    def __repr__(self):
        return f"<LiveContainerRepository task={self.task.name}>"

    async def delete(self, job, /):
        """Deleting a job from this repository will delete the containers for that job."""
        await self.task.kill(job, None)

    async def cache_key(self, job):
        return None


class LiveProcessRepository(Repository):
    """A repository where keys translate to containers running in process task.

    This repository is constructed automatically by a :class:`ProcessTask` or subclass and is linked as the ``live``
    repository. Do not construct this class manually.
    """

    _EXCLUDE_BACKUP = True

    def __init__(self, task: "ProcessTask"):
        super().__init__()
        self.task = task

    def footprint(self):
        return []

    def __getstate__(self):
        return (self.task.name,)

    async def unfiltered_iter(self):
        seen = set()
        for name, _ in await self.task.manager.live(self.task.name):
            if name in seen:
                continue
            seen.add(name)
            yield name

    async def contains(self, item, /):
        bluh = await self.task.manager.live(self.task.name)
        return any(item == job for job, _ in bluh)

    async def cache_key(self, job):
        return None

    def __repr__(self):
        return f"<LiveProcessRepository task={self.task.name}>"

    async def delete(self, job, /):
        """Deleting a job from this repository will delete the processes for that job."""
        await self.task.kill(job, None)


class LiveContainerSetRepository(Repository):
    _EXCLUDE_BACKUP = True

    def __init__(self, task: "ContainerSetTask"):
        super().__init__()
        self.task = task

    def footprint(self):
        return []

    def __getstate__(self):
        return (self.task.name,)

    async def unfiltered_iter(self):
        seen = set()
        for name, _ in await self.task.manager.live(self.task.name):
            if name in seen:
                continue
            seen.add(name)
            yield name

    async def contains(self, item, /):
        return any(item == job for job, _ in await self.task.manager.live(self.task.name))

    async def cache_key(self, job):
        return None

    def __repr__(self):
        return f"<LiveContainerSetRepository task={self.task.name}>"

    async def delete(self, job, /):
        await self.task.kill(job, None)
