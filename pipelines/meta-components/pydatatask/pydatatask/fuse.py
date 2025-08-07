# pylint: disable=missing-class-docstring,missing-module-docstring,missing-function-docstring,unused-argument
# pylint: disable=import-error
from __future__ import annotations

from typing import TYPE_CHECKING, cast
import os

from pydatafs.errors import FSInvalidError
from pydatafs.files import Directory, File, RWBufferedFile, Symlink
from pydatafs.filesystem import PyDataFS
import yaml

from pydatatask.utils import safe_load

from . import repository as repomodule
from . import task as taskmodule
from .pipeline import Pipeline

if TYPE_CHECKING:
    from pyfuse3 import FileHandleT, FileNameT, InodeT
else:
    InodeT = int
    FileHandleT = int
    FileNameT = bytes


class TaskListDir(Directory):
    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline
        super().__init__()

    async def get_children(self):
        for name, task in self.pipeline.tasks.items():
            yield name, TaskDir(task)

    async def get_child(self, name):
        task = self.pipeline.tasks.get(name, None)
        if task is None:
            return None
        return TaskDir(task)

    def __eq__(self, other):
        return self is other

    def __hash__(self):
        return id(self.pipeline)


class TaskDir(Directory):
    def __init__(self, task: taskmodule.Task):
        self.task = task
        super().__init__()

    async def get_children(self):
        for name, link in self.task.links.items():
            yield name, LinkDir(link)

    async def get_child(self, name):
        link = self.task.links.get(name, None)
        if link is None:
            return None
        return LinkDir(link)

    def __eq__(self, other):
        return type(self) is type(other) and self.task == other.task

    def __hash__(self):
        return hash(self.task)


class RepoDir(Directory):
    def __init__(self, repo: repomodule.Repository):
        self.repo = repo
        super().__init__()

        if isinstance(repo, repomodule.MetadataRepository):
            self.job_builder = self.metadata_builder
        elif isinstance(repo, repomodule.FileRepositoryBase):
            self.job_builder = self.symlink_builder
        elif isinstance(repo, repomodule.BlobRepository):
            self.job_builder = self.blob_builder
        elif isinstance(repo, repomodule.FilesystemRepository):
            self.job_builder = self.fs_builder
        else:
            self.job_builder = self.empty_builder

    def __eq__(self, other):
        return type(self) is type(other) and self.repo == other.repo

    def __hash__(self):
        return hash(self.repo)

    def metadata_builder(self, job: str):
        async def content():
            assert isinstance(self.repo, repomodule.MetadataRepository)
            if not await self.repo.contains(job):
                return bytearray()
            data = await self.repo.info(job)
            return bytearray(yaml.safe_dump(data).encode())

        async def writeback(data_bytes):
            assert isinstance(self.repo, repomodule.MetadataRepository)
            if not data_bytes:
                # we are PROBABLY doing open(x, O_TRUNC)
                # do not sync this. nobody wants the empty string to be valid yaml. fuck you
                return
            data = safe_load(bytes(data_bytes))
            await self.repo.dump(job, data)

        async def size():
            return 0

        return RWBufferedFile(
            identity=(self.repo, job),
            content=content,
            writeback=writeback,
            size=size,
        )

    def symlink_builder(self, job: str):
        assert isinstance(self.repo, repomodule.FileRepositoryBase)
        return Symlink((self.repo, job), str(self.repo.fullpath(job)))

    def blob_builder(self, job: str):
        async def content():
            assert isinstance(self.repo, repomodule.BlobRepository)
            if not await self.repo.contains(job):
                return bytearray()
            async with await self.repo.open(job, "rb") as fp:
                return bytearray(await fp.read())

        async def writeback(data):
            assert isinstance(self.repo, repomodule.BlobRepository)
            async with await self.repo.open(job, "wb") as fp:
                await fp.write(data)

        async def size():
            return 0

        return RWBufferedFile(
            identity=(self.repo, job),
            content=content,
            size=size,
            writeback=writeback,
        )

    def fs_builder(self, job: str):
        return FsRepoDir(cast(repomodule.FilesystemRepository, self.repo), job)

    def empty_builder(self, job: str):
        return RWBufferedFile(identity=(self.repo, job), content=b"This repository is not readable\n")

    async def get_children(self):
        async for job in self.repo:
            yield job, self.job_builder(job)

    async def get_child(self, name):
        if await self.repo.contains(name):
            return self.job_builder(name)
        return None

    async def create(self, name: str, mode, flags) -> File:
        if isinstance(self.repo, repomodule.MetadataRepository):
            return self.job_builder(name)  # type: ignore
        elif isinstance(self.repo, repomodule.FileRepositoryBase):
            raise FSInvalidError()
        else:
            return self.job_builder(name)  # type: ignore

    async def unlink_child(self, name: str):
        await self.repo.delete(name)


class LinkDir(RepoDir):
    def __init__(self, link: taskmodule.Link):
        self.link = link
        super().__init__(link.repo)


class FsRepoDir(Directory):
    def __init__(self, repo: repomodule.FilesystemRepository, job: str, path: str = "."):
        self.repo = repo
        self.job = job
        self.path = path
        super().__init__(mode=0o555)

    async def get_children(self):
        async for member in self.repo.iterdir(self.job, self.path):
            stuff = await self.get_child(member)
            if stuff is not None:
                yield member, stuff

    async def get_child(self, name: str):
        fullpath = f"{self.path}/{name}"
        ty = await self.repo.get_type(self.job, fullpath)
        if ty is None:
            return None
        if ty == repomodule.FilesystemType.FILE:
            return FsRepoFile(self.repo, self.job, fullpath)
        elif ty == repomodule.FilesystemType.DIRECTORY:
            return FsRepoDir(self.repo, self.job, fullpath)
        elif ty == repomodule.FilesystemType.SYMLINK:
            return Symlink((self.repo, self.job, fullpath), await self.repo.readlink(self.job, fullpath))
        else:
            raise TypeError()

    def __hash__(self):
        return hash((self.repo, self.job, self.path))

    def __eq__(self, other):
        return type(self) is type(other) and (self.repo, self.job, self.path) == (other.repo, other.job, other.path)


class FsRepoFile(File):
    def __init__(self, repo: repomodule.FilesystemRepository, job: str, path: str):
        self.repo = repo
        self.job = job
        self.path = path
        self._fp = None
        self._fp_mgr = None
        self._off = None
        super().__init__(mode=0o444)

    def __hash__(self):
        return hash((self.repo, self.job, self.path))

    def __eq__(self, other):
        return type(self) is type(other) and (self.repo, self.job, self.path) == (other.repo, other.job, other.path)

    async def read(self, off, size):
        if self._fp is None or self._off is None or off < self._off:
            self._fp_mgr = await self.repo.open(self.job, self.path)
            self._fp = await self._fp_mgr.__aenter__()
            self._off = 0

        while self._off > off:
            data = await self._fp.read(self._off - off)
            self._off += len(data)

        if self._off != off:
            raise Exception("Underlying file object is misbehaving")

        data = bytearray()
        while len(data) < size:
            datum = await self._fp.read(size - len(data))
            self._off += len(datum)
            if not datum:
                break
            data.extend(datum)

        if len(data) > size:
            raise Exception("Underlying file object is misbehaving")

        return bytes(data)


async def main(pipeline: Pipeline, path: str, debug: bool):
    stats = os.stat(path)
    fs = PyDataFS("pydatatask", TaskListDir(pipeline), uid=stats.st_uid, gid=stats.st_gid, debug=debug)
    await fs.run(path)
