"""This module contains repository base classes as well as repository combinators and the simple filesystem
repositories."""

import contextlib
import json
import tempfile
import time
from typing import (
    Any,
    AsyncContextManager,
    AsyncGenerator,
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
)
from typing import Counter as TypedCounter
from typing import Dict, Iterable, List, Literal, Optional, Set, Union, overload
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
import asyncio.subprocess
import inspect
import io
import logging
import os
import string
import uuid
import aiofiles.os
import jsonschema
import orjson
import yaml

from .. import repository as repomodule
from .. import task as taskmodule
from ..utils import (
    AReadStreamManager,
    AReadText,
    AReadTextProto,
    AWriteStreamDrainer,
    AWriteStreamManager,
    AWriteText,
    AWriteTextProto,
    async_copyfile,
    async_copyfile_close,
    asyncasynccontextmanager,
    roundrobin,
    safe_load,
)

from datetime import datetime, timedelta

l = logging.getLogger(__name__)


# Helper Functions
def job_getter(f):
    """Use this function to annotate non-abstract methods which take a job identifier as their first parameter.

    This is used by RelatedItemRepository to automatically translate job identifiers to related ones.
    """
    if not inspect.iscoroutinefunction(f):
        raise TypeError("only async functions can be job_getters")
    f.is_job_getter = True
    return f


class StrDict(dict):
    """A dict with a custom str representation.

    Useful for templating.
    """

    def __init__(self, __val, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.string = __val

    def __str__(self):
        return self.string


# Base Classes
class Repository(ABC):
    """A repository is a key-value store where the keys are names of jobs. Since the values have unspecified
    semantics, the only operations you can do on a generic repository are query for keys.

    A repository can be async-iterated to get a listing of its members.
    """

    def __init__(self):
        self.annotations: Dict[str, str] = {}
        self.compress_backup: bool = False
        self.__id__ = str(uuid.uuid4())

    CHARSET = CHARSET_START_END = string.ascii_letters + string.digits

    def cache_flush(self, soft=False):
        """Flush any in-memory caches held for this repository."""

    @abstractmethod
    def footprint(self):
        """Yield all the repositories which are lowest-level representations of stored data."""
        raise NotImplementedError

    @classmethod
    def is_valid_job_id(cls, job: str, /):
        return True
        """Determine whether the given job identifier is valid, i.e. that it contains only valid characters (numbers
        and letters by default)."""
        return (
            0 < len(job) <= 64
            and all(c in cls.CHARSET for c in job)
            and job[0] in cls.CHARSET_START_END
            and job[-1] in cls.CHARSET_START_END
        )

    async def filter_jobs(self, iterator: AsyncIterable[str], /) -> AsyncIterator[str]:
        """Apply `is_valid_job_id` as a filter to an async iterator."""
        async for job in iterator:
            if self.is_valid_job_id(job):
                yield job
            else:
                l.warning("Skipping %s %s - not a valid job id", self, repr(job))

    async def contains(self, item: str, /):
        """Determine whether the given job identifier is present in this repository.

        The default implementation is quite inefficient; please override this if possible.
        """
        async for x in self:
            if x == item:
                return True
        return False

    def __aiter__(self) -> AsyncIterator[str]:
        return self.filter_jobs(self.unfiltered_iter())

    async def keys(self) -> List[str]:
        """Return a list of all keys in the repository."""
        return [x async for x in self]

    @abstractmethod
    def __getstate__(self) -> Any:
        raise NotImplementedError

    @abstractmethod
    def unfiltered_iter(self) -> AsyncGenerator[str, None]:
        """The core method of Repository.

        Implement this to produce an iterable of every string which could potentially be a job identifier present in
        this repository. When the repository is iterated directly, this will be filtered by `filter_jobs`.
        """
        raise NotImplementedError

    async def template(
        self,
        job: str,
        task: taskmodule.Task,
        kind: taskmodule.LinkKind,
        link_name: str,
        hostjob: Optional[str] = None,
    ) -> taskmodule.TemplateInfo:
        """Returns an arbitrary piece of data related to job.

        Notably, this is used during templating. This should do something meaningful even if the repository does not
        contain the requested job.

        TODO: this docstring is woefully outdated. See LinkKind.
        """

        force_path = task.links[link_name].force_path
        content_keyed_md5 = task.links[link_name].content_keyed_md5
        assert not content_keyed_md5 or isinstance(self, (repomodule.BlobRepository, repomodule.MetadataRepository))

        if kind in (taskmodule.LinkKind.InputId, taskmodule.LinkKind.OutputId):
            return taskmodule.TemplateInfo(job)
        if kind in (taskmodule.LinkKind.InputRepo, taskmodule.LinkKind.OutputRepo):
            return taskmodule.TemplateInfo(FixedItemRepository(self, job))
        if kind == taskmodule.LinkKind.InputFilepath:
            if force_path is None:
                filepath = task.mktemp(f"input-{link_name}-{job}")
            else:
                filepath = force_path.format(link_name=link_name, job=job)
            cache_key = await task._repo_related(link_name).cache_key(job)
            return taskmodule.TemplateInfo(filepath, preamble=task.mk_repo_get(filepath, link_name, job, cache_key))
        if kind == taskmodule.LinkKind.OutputFilepath:
            if force_path is None:
                filepath = task.mktemp(f"output-{link_name}-{job}")
            else:
                filepath = force_path.format(link_name=link_name, job=job)
            preamble = (
                task.mk_mkdir(filepath)
                if isinstance(task.links[link_name].repo, repomodule.FilesystemRepository)
                else ""
            )
            put = task.mk_repo_put(filepath, link_name, job)

            if content_keyed_md5:
                cokey_dirs = {}
                for k in task.links[link_name].cokeyed:
                    cofilepath = task.mktemp(f"output-{link_name}-{k}-{job}")
                    cokey_dirs[k] = cofilepath
                    preamble += (
                        task.mk_mkdir(cofilepath)
                        if isinstance(task.links[link_name].cokeyed[k], repomodule.FilesystemRepository)
                        else ""
                    )
                    put += task.mk_repo_put_cokey(cofilepath, link_name, k, "$UPLOAD_JOB", hostjob=job)
                result = StrDict(filepath, {"cokeyed": cokey_dirs})
            else:
                result = filepath
            return taskmodule.TemplateInfo(result, epilogue=put, preamble=preamble)

        if kind == taskmodule.LinkKind.StreamingOutputFilepath:
            if force_path is None:
                filepath = task.mktemp(f"streaming-output-{link_name}-{job}")
            else:
                filepath = force_path.format(link_name=link_name, job=job)
            preamble, epilogue, extra_dirs = task.mk_watchdir_upload(
                filepath,
                link_name,
                hostjob,
                mkdir=force_path is None,
                DANGEROUS_filename_is_key=task.links[link_name].DANGEROUS_filename_is_key,
                content_keyed_md5=task.links[link_name].content_keyed_md5,
            )
            return taskmodule.TemplateInfo(StrDict(filepath, extra_dirs), preamble=preamble, epilogue=epilogue)
        if kind == taskmodule.LinkKind.StreamingInputFilepath:
            if force_path is None:
                filepath = task.mktemp(f"streaming-input-{link_name}-{job}")
            else:
                filepath = force_path.format(link_name=link_name, job=job)
            preamble, extra_dirs = task.mk_watchdir_download(filepath, link_name, job)
            return taskmodule.TemplateInfo(StrDict(filepath, extra_dirs), preamble=preamble)
        if kind == taskmodule.LinkKind.RequestedInput:
            preamble, func = task.mk_download_function(link_name)
            return taskmodule.TemplateInfo(func, preamble=preamble)
        if kind == taskmodule.LinkKind.Cancel:
            return taskmodule.TemplateInfo("")
        raise ValueError(f"{type(self)} cannot be templated as {kind} for {task}")

    @abstractmethod
    async def delete(self, job: str, /):
        """Delete the given job from the repository.

        This should succeed even if the job is not present in this repository.
        """
        raise NotImplementedError

    async def validate(self):
        """Override this method to raise an exception if for any reason the repository is misconfigured.

        This will be automatically called by the pipeline on opening.
        """

    @abstractmethod
    def cache_key(self, job: str) -> Awaitable[Optional[str]]:
        raise NotImplementedError


class MetadataRepository(Repository, ABC):
    """A metadata repository has values which are small, structured data, and loads them entirely into memory,
    returning the structured data from the `info` method."""

    def __init__(self, schema: Optional[Any] = None):
        super().__init__()
        self.schema = schema

    def schema_validate(self, data: Any) -> None:
        """Check if the given data matches the provided repository schema.

        Will raise an exception if it does not.
        """
        if self.schema is None:
            return
        jsonschema.validate(data, self.schema)

    def construct_backup_repo(self, path: Path, force_compress: Optional[bool] = None) -> "MetadataRepository":
        """Construct a repository appropriate for backing up this repository to the given path."""
        if (self.compress_backup or force_compress is True) and force_compress is not False:
            l.warning("Compressed backups not yet implemented for %s", type(self))
        return YamlMetadataFileRepository(path, extension=".yaml")

    async def template(
        self,
        job: str,
        task: taskmodule.Task,
        kind: taskmodule.LinkKind,
        link_name: str,
        hostjob: Optional[str] = None,
    ) -> taskmodule.TemplateInfo:
        if kind != taskmodule.LinkKind.InputMetadata:
            return await super().template(job, task, kind, link_name, hostjob)
        info = await self.info(job)
        return taskmodule.TemplateInfo(info)

    @abstractmethod
    async def info(self, job: str, /) -> Any:
        """Retrieve the data with key ``job`` from the repository."""
        raise NotImplementedError

    async def info_all(self) -> Dict[str, Any]:
        """Produce a mapping from every job present in the repository to its corresponding info.

        The default implementation is somewhat inefficient; please override it if there is a more effective way to load
        all info.
        """
        return {job: await self.info(job) async for job in self}

    @abstractmethod
    async def dump(self, job: str, data: Any, /):
        """Insert ``data`` into the repository with key ``job``."""
        raise NotImplementedError

    def map(
        self,
        func: Callable[[str, Any], Awaitable[Any]],
        extra_footprint: Iterable[Repository],
        filt: Optional[Callable[[str], Awaitable[bool]]] = None,
        allow_deletes=False,
    ) -> "MapRepository":
        """Generate a :class:`MapRepository` based on this repository and the given parameters."""
        return MapRepository(self, func, extra_footprint, filt, allow_deletes=allow_deletes)


class MapRepository(MetadataRepository):
    """A MapRepository is a repository which uses arbitrary functions to map and filter results from a base
    repository."""

    def __init__(
        self,
        base: MetadataRepository,
        func: Callable[[str, Any], Awaitable[Any]],
        extra_footprint: Iterable[Repository],
        filt: Optional[Callable[[str], Awaitable[bool]]] = None,
        filter_all: Optional[Callable[[Dict[str, Any]], AsyncIterable[str]]] = None,
        allow_deletes=False,
    ):
        """
        :param func: The function to use to translate the base repository's info results into the mapped info
                     results.
        :param filt: Optional: An async function to use to determine whether a given key should be considered part of
                     the mapped repository.
        :param allow_deletes: Whether the delete operation will do anything on the mapped repository.
        """
        super().__init__()
        self.base = base
        self.func = func
        self.filter = filt
        self.filter_all = filter_all
        self.allow_deletes = allow_deletes
        self.extra_footprint = extra_footprint

    def footprint(self):
        yield from self.base.footprint()
        for child in self.extra_footprint:
            yield from child.footprint()

    def cache_flush(self, soft=False):
        self.base.cache_flush(soft=soft)
        for child in self.extra_footprint:
            child.cache_flush(soft=soft)

    def __getstate__(self):
        return (self.base, self.func, self.filter, self.allow_deletes)

    async def contains(self, item, /):
        if self.filter is None or await self.filter(item):
            return await self.base.contains(item)
        return False

    async def delete(self, job, /):
        if self.allow_deletes:
            await self.base.delete(job)

    async def unfiltered_iter(self):
        async for item in self.base.unfiltered_iter():
            if self.filter is None or await self.filter(item):
                yield item

    async def info(self, job, /):
        return await self.func(job, await self.base.info(job))

    async def info_all(self) -> Dict[str, Any]:
        result = await self.base.info_all()
        if self.filter_all is not None:
            result = {k: await self.func(k, result[k]) async for k in self.filter_all(result)}
        else:
            to_remove = []
            for k, v in result.items():
                if self.filter is None or await self.filter(k):
                    result[k] = await self.func(k, v)
                else:
                    to_remove.append(k)
            for k in to_remove:
                result.pop(k)
        return result

    async def dump(self, job: str, data: Any, /):
        raise TypeError("Do not try to dump into a map repository lol")

    async def cache_key(self, job: str):
        return None


class FilterRepository(Repository):
    """A FilterRepository is a repository which uses arbitrary functions to filter results from a base
    repository."""

    def __init__(
        self,
        base: Repository,
        filt: Optional[Callable[[str], Awaitable[bool]]] = None,
        allow_deletes=False,
        extra_footprint: Optional[List[Repository]] = None,
    ):
        """
        :param func: The function to use to translate the base repository's info results into the mapped info
                     results.
        :param filt: Optional: An async function to use to determine whether a given key should be considered part of
                     the mapped repository.
        :param allow_deletes: Whether the delete operation will do anything on the mapped repository.
        """
        super().__init__()
        self.base = base
        self.filter = filt
        self.allow_deletes = allow_deletes
        self.extra_footprint = extra_footprint or []

    def __getstate__(self):
        return (self.base, self.filter, self.allow_deletes)

    def footprint(self):
        yield from self.base.footprint()
        for repo in self.extra_footprint:
            yield from repo.footprint()

    def cache_flush(self, soft=False):
        self.base.cache_flush(soft=soft)
        for repo in self.extra_footprint:
            repo.cache_flush(soft=soft)

    async def contains(self, item, /):
        if self.filter is None or await self.filter(item):
            return await self.base.contains(item)
        return False

    async def delete(self, job, /):
        if self.allow_deletes:
            await self.base.delete(job)

    async def unfiltered_iter(self):
        async for item in self.base.unfiltered_iter():
            if self.filter is None or await self.filter(item):
                yield item

    async def cache_key(self, job):
        return await self.base.cache_key(job)


class FilterMetadataRepository(FilterRepository, MetadataRepository):
    """A filter repository that is also a metadata repository."""

    def __init__(
        self,
        base: MetadataRepository,
        filt: Optional[Callable[[str], Awaitable[bool]]] = None,
        filter_all: Optional[Callable[[Dict[str, Any]], AsyncIterator[str]]] = None,
        allow_deletes=False,
        extra_footprint: Optional[List[Repository]] = None,
    ):
        if filt is None:
            assert filter_all is not None

            async def f(k):
                try:
                    await filter_all({k: await self.info(k)}).__anext__()
                except StopAsyncIteration:
                    return False
                else:
                    return True

            super().__init__(base, f, allow_deletes=allow_deletes, extra_footprint=extra_footprint)
        else:
            super().__init__(base, filt, allow_deletes=allow_deletes, extra_footprint=extra_footprint)
        self.filter_all = filter_all

    base: MetadataRepository

    async def info(self, job, /):
        return await self.base.info(job)

    async def info_all(self) -> Dict[str, Any]:
        result = await self.base.info_all()
        if self.filter_all is not None:
            result = {k: result[k] async for k in self.filter_all(result)}
        else:
            to_remove = []
            for k in result:
                if self.filter is not None and await self.filter(k):
                    to_remove.append(k)
            for k in to_remove:
                result.pop(k)
        return result

    async def dump(self, job: str, data: Any, /):
        await self.base.dump(job, data)


class BlobRepository(Repository, ABC):
    """A blob repository has values which are flat data blobs that can be streamed for reading or writing."""

    def construct_backup_repo(self, path: Path, force_compress: Optional[bool] = None) -> "BlobRepository":
        """Construct a repository appropriate for backing up this repository to the given path."""
        if (self.compress_backup or force_compress is True) and force_compress is not False:
            return CompressedBlobRepository(FileRepository(path, extension=".gz"))
        else:
            return FileRepository(path)

    @overload
    @abstractmethod
    async def open(self, job: str, mode: Literal["r"]) -> AsyncContextManager[AReadTextProto]: ...

    @overload
    @abstractmethod
    async def open(self, job: str, mode: Literal["w"]) -> AsyncContextManager[AWriteTextProto]: ...

    @overload
    @abstractmethod
    async def open(self, job: str, mode: Literal["rb"]) -> AReadStreamManager: ...

    @overload
    @abstractmethod
    async def open(self, job: str, mode: Literal["wb"]) -> AWriteStreamManager: ...

    @abstractmethod
    async def open(self, job, mode="r"):
        """Open the given job's value as a stream for reading or writing, in text or binary mode."""
        raise NotImplementedError

    async def blobdump(self, job: str, value: Union[bytes, str]):
        """
        Convenience function: dump the entire contents of a string or bytestring into a job.
        """
        if isinstance(value, (bytes, memoryview, bytearray)):
            async with await self.open(job, "wb") as fp:
                await fp.write(value)
        else:
            async with await self.open(job, "w") as fp:
                await fp.write(value)

    async def blobinfo(self, job: str) -> bytes:
        """
        Convenience function: read the entire contents of a job into a bytestring.
        """
        async with await self.open(job, "rb") as fp:
            return await fp.read()


class FileRepositoryBase(Repository, ABC):
    """A file repository is a local directory where each job identifier is a filename, optionally suffixed with an
    extension before hitting the filesystem.

    This is an abstract base class for other file repositories which have more to say about what is found at these
    filepaths.
    """

    def __init__(self, basedir: Union[str, Path], extension: str = "", case_insensitive: bool = False):
        super().__init__()
        self.basedir = Path(basedir)
        self.extension = extension
        self.case_insensitive = case_insensitive

    def __getstate__(self):
        return (self.basedir, self.extension, self.case_insensitive)

    async def contains(self, item, /):
        return await aiofiles.os.path.exists(self.basedir / (item + self.extension))

    def __repr__(self):
        return f'<{type(self).__name__} {self.basedir / ("*" + self.extension)}>'

    async def unfiltered_iter(self):
        for name in await aiofiles.os.listdir(self.basedir):
            if self.case_insensitive:
                cond = name.lower().endswith(self.extension.lower())
            else:
                cond = name.endswith(self.extension)
            if cond:
                yield name[: -len(self.extension) if self.extension else None]

    async def validate(self):
        self.basedir.mkdir(exist_ok=True, parents=True)
        if not os.access(self.basedir, os.W_OK):
            raise PermissionError(f"Cannot write to {self.basedir}")

        await super().validate()

    def fullpath(self, job) -> Path:
        """Construct the full local path of the file corresponding to ``job``."""
        return self.basedir / (job + self.extension)

    async def cache_key(self, job):
        return f"file:{self.basedir}/{job}"

@contextlib.asynccontextmanager
async def atomically_written_file_via_tmpfile(path, mode):
    '''
    Open a tempfile in the given mode and return it instead of the real file. When the context manager
    exits, move the tempfile to the real path. This should be used for atomic writes.

    This is a context manager, so it should be used with async with. For example:

    async with one_shot_moved_tmpfile('path/to/file', 'w') as fp:
        await fp.write('data')
    '''

    assert mode in ('w', 'wb')

    # First, copy the file to a temporary location
    with tempfile.NamedTemporaryFile(mode=mode, delete=False) as tmp_fp:
        async with aiofiles.open(tmp_fp.name, mode) as tmp_fp_async:
            yield tmp_fp_async

    # Then, move the temporary file to the real path
    await aiofiles.os.rename(tmp_fp.name, path)


class FileRepository(FileRepositoryBase, BlobRepository):  # BlobFileRepository?
    """A file repository whose members are files, treated as streamable blobs."""

    def footprint(self):
        yield self

    @job_getter
    async def open(self, job, mode="r"):
        if not self.is_valid_job_id(job):
            raise KeyError(f"Invalid job id {job} for {self}")
        if mode in ('w', 'wb'):
            return atomically_written_file_via_tmpfile(self.fullpath(job), mode)
        return aiofiles.open(self.fullpath(job), mode)  # type: ignore

    def open_sync_for_read(self, job, mode="r"):
        #if not self.is_valid_job_id(job):
        #    raise KeyError(f"Invalid job id {job} for {self}")
        fp = self.fullpath(job)
        #l.info(f"Opening {fp} for read")
        return open(fp, mode)

    async def delete(self, job, /):
        try:
            await aiofiles.os.unlink(self.fullpath(job))
        except FileNotFoundError:
            pass


class FunctionCallMetadataRepository(MetadataRepository):
    """A metadata repository which contains a function used to generate the info for each job."""

    def __init__(self, info: Callable[[str], Any], domain: Repository, extra_footprint: Iterable[Repository]):
        super().__init__()
        self._info = info
        self._domain = domain
        self._extra_footprint = extra_footprint

    def footprint(self):
        yield from self._domain.footprint()
        for child in self._extra_footprint:
            yield from child.footprint()

    def cache_flush(self, soft=False):
        self._domain.cache_flush(soft=soft)
        for child in self._extra_footprint:
            child.cache_flush(soft=soft)

    async def cache_key(self, job):
        return None

    def __getstate__(self):
        return (self._info, self._domain)

    async def contains(self, item: str, /):
        return await self._domain.contains(item)

    async def delete(self, job: str, /):
        return

    async def unfiltered_iter(self):
        async for job in self._domain:
            yield job

    @job_getter
    async def info(self, job: str, /):
        result = self._info(job)
        if inspect.iscoroutine(result):
            result = await result
        return result

    async def dump(self, job: str, data: Any, /):
        raise TypeError("Simply don't!")


class RelatedItemRepository(Repository):
    """A repository which returns items from another repository based on following a related-item lookup."""

    def __init__(
        self,
        base_repository: Repository,
        translator_repository: MetadataRepository,
        allow_deletes=False,
        prefetch_lookup=True,
    ):
        """
        :param base_repository: The repository from which to return results based on translated keys. The resulting
                                repository will duck-type as the same type as the base.
        :param translator_repository: A repository whose info() will be used to translate keys:
                                      ``info(job) == translated_job``.
        :param allow_deletes: Whether the delete operation on this repository does anything. If enabled, it will delete
                              only from the base repository.
        :param prefetch_lookup: Whether to cache the entirety of the translator repository in memory to improve
                                performance.
        """
        super().__init__()
        self.base_repository = base_repository
        self.translator_repository = translator_repository
        self.allow_deletes = allow_deletes
        self.prefetch_lookup_setting = prefetch_lookup
        self.prefetch_lookup: Optional[Dict[str, Any]] = None

    def footprint(self):
        yield from self.base_repository.footprint()
        yield from self.translator_repository.footprint()

    def cache_flush(self, soft=False):
        self.base_repository.cache_flush(soft=soft)
        self.translator_repository.cache_flush(soft=soft)
        self.prefetch_lookup = None

    def __getstate__(self):
        return (self.base_repository, self.translator_repository, self.allow_deletes, self.prefetch_lookup_setting)

    def __repr__(self):
        return f"<{type(self).__name__} {self.base_repository} by {self.translator_repository}>"

    async def _lookup(self, item):
        if self.prefetch_lookup is None and self.prefetch_lookup_setting:
            self.prefetch_lookup = await self.translator_repository.info_all()
        if self.prefetch_lookup:
            return self.prefetch_lookup.get(item)
        else:
            return await self.translator_repository.info(item)

    async def contains(self, item, /):
        basename = await self._lookup(item)
        if basename is None:
            return False
        return await self.base_repository.contains(basename)

    async def cache_key(self, job):
        basename = await self._lookup(job)
        if basename is None:
            return None
        return await self.base_repository.cache_key(basename)

    async def delete(self, job, /):
        if not self.allow_deletes:
            return

        basename = await self._lookup(job)
        if basename is None:
            return

        await self.base_repository.delete(basename)

    def __getattr__(self, item):
        v = getattr(self.base_repository, item)
        if not getattr(v, "is_job_getter", False):
            return v

        async def inner(job, *args, **kwargs):
            basename = await self._lookup(job)
            if basename is None:
                raise LookupError(job)
            return await v(basename, *args, **kwargs)

        return inner

    async def unfiltered_iter(self):
        base_contents = {x async for x in self.base_repository}
        # translator_repository_contents = [x async for x in self.translator_repository]
        # l.warning("RelatedItemRepository: %d items in base, %d items in translator repository, ratio= %.2f",
        #           len(base_contents), len(translator_repository_contents),
        #           len(base_contents) / len(translator_repository_contents) if translator_repository_contents else 0)
        async for item in self.translator_repository:
            basename = await self._lookup(item)
            if basename is not None and basename in base_contents:
                yield item


class RelatedItemMetadataRepository(RelatedItemRepository, MetadataRepository):
    """It's a `RelatedItemRepository` but additionally a `MetadataRepository`.

    Neat!
    """

    base_repository: MetadataRepository

    def __init__(
        self,
        base_repository: MetadataRepository,
        translator_repository: MetadataRepository,
        allow_deletes=False,
        prefetch_lookup=True,
    ):
        super().__init__(
            base_repository, translator_repository, allow_deletes=allow_deletes, prefetch_lookup=prefetch_lookup
        )

    @job_getter
    async def info(self, job, /):
        """Perform the info lookup for the base repository."""
        assert isinstance(self.base_repository, MetadataRepository)
        basename = await self._lookup(job)
        if basename is None:
            raise LookupError(job)

        return await self.base_repository.info(basename)

    async def dump(self, job: str, data: Any, /):
        raise TypeError("Simply don't!")


class FixedItemRepository:
    """The result of templating with the InputRepo or OutputRepo kind.

    Provides access to all job-getter async functions from the given repository, but with the job parameter already
    filled in.
    """

    def __init__(self, repo: Repository, job: str):
        super().__init__()
        self._repo = repo
        self._job = job

    def __getattr__(self, item):
        v = getattr(self._repo, item)
        if not getattr(v, "is_job_getter", False):
            raise AttributeError(item)

        async def inner(*args, **kwargs):
            return await v(self._job, *args, **kwargs)

        return inner


class AggregateAndRepository(Repository):
    """A repository which is said to contain a job if all its children also contain that job."""

    def __init__(self, **children: Repository):
        super().__init__()
        assert children
        self.children = children

    def footprint(self):
        for child in self.children.values():
            yield from child.footprint()

    def cache_flush(self, soft=False):
        for child in self.children.values():
            child.cache_flush(soft=soft)

    async def cache_key(self, job):
        return None

    def __getstate__(self):
        return (self.children,)

    async def unfiltered_iter(self):
        counting: "TypedCounter[str]" = Counter()
        async for item in roundrobin([child.unfiltered_iter() for child in self.children.values()]):
            counting[item] += 1
            if counting[item] == len(self.children):
                yield item

    async def contains(self, item, /):
        for child in self.children.values():
            if not await child.contains(item):
                return False
        return True

    async def delete(self, job, /):
        """Deleting a job from an aggregate And repository deletes the job from all of its children."""
        for child in self.children.values():
            await child.delete(job)


class AggregateOrRepository(Repository):
    """A repository which is said to contain a job if any of its children also contain that job."""

    def __init__(self, **children: Repository):
        super().__init__()
        assert children
        self.children = children

    def footprint(self):
        for child in self.children.values():
            yield from child.footprint()

    def cache_flush(self, soft=False):
        for child in self.children.values():
            child.cache_flush(soft=soft)

    async def cache_key(self, job):
        return None

    def __getstate__(self):
        return (self.children,)

    async def unfiltered_iter(self):
        seen = set()
        for child in self.children.values():
            async for item in child.unfiltered_iter():
                if item in seen:
                    continue
                seen.add(item)
                yield item

    async def contains(self, item, /):
        for child in self.children.values():
            if await child.contains(item):
                return True
        return False

    async def delete(self, job, /):
        """Deleting a job from an aggregate Or repository deletes the job from all of its children."""
        for child in self.children.values():
            await child.delete(job)


class BlockingRepository(Repository):
    """A class that is said to contain a job if ``source`` contains it and ``unless`` does not contain it."""

    def __init__(self, source: Repository, unless: Repository, enumerate_unless=True):
        super().__init__()
        self.source = source
        self.unless = unless
        self.enumerate_unless = enumerate_unless

    def footprint(self):
        yield from self.source.footprint()
        yield from self.unless.footprint()

    def cache_flush(self, soft=False):
        self.source.cache_flush(soft=soft)
        self.unless.cache_flush(soft=soft)

    async def cache_key(self, job):
        return await self.source.cache_key(job)

    def __getstate__(self):
        return (self.source, self.unless, self.enumerate_unless)

    async def unfiltered_iter(self):
        if self.enumerate_unless:
            blocked = set()
            async for x in self.unless.unfiltered_iter():
                blocked.add(x)
        else:
            blocked = None
        async for item in self.source.unfiltered_iter():
            if blocked is not None and item in blocked:
                continue
            if not self.enumerate_unless and self.unless.contains(item):
                continue
            yield item

    async def contains(self, item, /):
        return await self.source.contains(item) and not await self.unless.contains(item)

    async def delete(self, job, /):
        await self.source.delete(job)


class CachedSerializedMetadataRepository(MetadataRepository, ABC):
    """A metadata repository based on a blob repository. When info is accessed, it will **load the target file into
    memory**, parse it as yaml, and return the resulting object.

    This is a base class, and must be overridden to implement the blob loading portion.
    """

    def __init__(self, blob: BlobRepository, deserialize=safe_load, serialize=yaml.safe_dump):
        super().__init__()
        self.blob = blob
        self.yaml_load_cache = {}
        self.yaml_load_cache_by_job = {}
        self._info_all_cache = None
        self.serialize = serialize
        self.deserialize = deserialize

    # better backup
    def footprint(self):
        yield self

    def cache_flush(self, soft=False):
        self.blob.cache_flush(soft=soft)
        if not soft:
            self.yaml_load_cache.clear()
            self.yaml_load_cache_by_job.clear()
        # This needs to flush every time because the cache of the entire repository is invalidated
        self._info_all_cache = None

    def __getstate__(self):
        return (self.blob,)

    def unfiltered_iter(self):
        return self.blob.unfiltered_iter()

    def delete(self, job, /):
        return self.blob.delete(job)

    async def validate(self):
        await self.blob.validate()
        await super().validate()

    async def info_all(self) -> Dict[str, Any]:
        """Produce a mapping from every job present in the repository to its corresponding info.

        The default implementation is somewhat inefficient; please override it if there is a more effective way to load
        all info.
        """
        #if self._info_all_cache is not None:
        #    return self._info_all_cache

        USE_SYNC = True
        jobs = [job async for job in self]

        num_jobs = len(jobs)

        if USE_SYNC and isinstance(self.blob, FileRepository):
            res = {}
            if num_jobs > 100:
                s = time.time()
            res = {job: self.info_sync(job) for job in jobs}
            if num_jobs > 100:
                e = time.time()
                l.info(f"Loaded {num_jobs} jobs in {e-s} seconds for {self.blob}")
            #self._info_all_cache = res
            return res


        return {job: await self.info(job) async for job in self}

    def info_sync(self, job):
        ch = self.yaml_load_cache_by_job.get(job)
        if ch:
            return ch
        try:
            # always use sync path now
            with self.blob.open_sync_for_read(job, "rb") as fp:
                s = fp.read()
        except (LookupError, FileNotFoundError):
            return {}
        
        if s not in self.yaml_load_cache:
            start_time = time.time()
            result = self.deserialize(s)
            # cache access needs thread safety if shared
            self.yaml_load_cache[s] = result
            end_time = time.time()
            if end_time - start_time > 1:
                l.warning("Loading %s on %s, %s: took excessively long: %ss > 1s", 
                        job, self, self.blob, end_time - start_time)
        else:
            result = self.yaml_load_cache[s]
        
        self.yaml_load_cache_by_job[job] = result
        return result

    @job_getter
    async def info(self, job, /):
        if job in self.yaml_load_cache_by_job:
            return self.yaml_load_cache_by_job[job]
        try:
            #l.info(f"Loading {self.blob} {job}")
            if isinstance(self.blob, FileRepository):
                fp = self.blob.open_sync_for_read(job, "rb")
                s = fp.read()
                fp.close()
            else:
                async with await self.blob.open(job, "rb") as fp:
                    s = await fp.read()
        except (LookupError, FileNotFoundError):
            return {}

        if s not in self.yaml_load_cache:
            start_time = time.time()
            self.yaml_load_cache[s] = self.deserialize(s)
            self.yaml_load_cache_by_job[job] = self.yaml_load_cache[s]
            end_time = time.time()
            if end_time - start_time > 1:
                l.warning("Loading %s on %s, %s: took excessively long: %ss > 1s", job, self, self.blob, end_time - start_time)
        result = self.yaml_load_cache[s]
        return result

    @job_getter
    async def dump(self, job, data, /):
        self.schema_validate(data)
        if not self.blob.is_valid_job_id(job):
            raise KeyError(job)
        s = self.serialize(data)
        async with await self.blob.open(job, "w") as fp:
            await fp.write(s)

    async def cache_key(self, job):
        return await self.blob.cache_key(job)

class YamlMetadataRepository(CachedSerializedMetadataRepository):
    """A metadata repository based on a blob repository, where the blobs are yaml files."""
    def __init__(self, blob, deserialize=safe_load, serialize=yaml.safe_dump):
        super().__init__(blob, deserialize, serialize)


def serialize_json(s):
    return orjson.dumps(s).decode('utf-8')
class JsonMetadataRepository(CachedSerializedMetadataRepository):
    """A metadata repository based on a blob repository, where the blobs are json files."""
    def __init__(self, blob, deserialize=safe_load, serialize=serialize_json):
        super().__init__(blob, deserialize, serialize)


class YamlMetadataFileRepository(YamlMetadataRepository):
    """A metadata repository based on a file blob repository."""

    def __init__(self, basedir: Union[str, Path], extension: str = ".yaml", case_insensitive: bool = False):
        super().__init__(FileRepository(basedir, extension=extension, case_insensitive=case_insensitive))

class JsonMetadataFileRepository(JsonMetadataRepository):
    """A metadata repository based on a file blob repository."""

    def __init__(self, basedir: Union[str, Path], extension: str = ".json", case_insensitive: bool = False):
        super().__init__(FileRepository(basedir, extension=extension, case_insensitive=case_insensitive))


class ExecutorLiveRepo(Repository):
    """A repository where keys translate to running jobs in an ExecutorTask.

    This repository is constructed automatically and is linked as the ``live`` repository. Do not construct this class
    manually.
    """

    _EXCLUDE_BACKUP = True

    def __init__(self, task: "taskmodule.ExecutorTask"):
        super().__init__()
        self.task = task

    def footprint(self):
        return []

    def __getstate__(self):
        return (self.task.name,)

    def __repr__(self):
        return f"<{type(self).__name__} task={self.task.name}>"

    async def unfiltered_iter(self):
        for job in self.task.rev_jobs:
            yield job

    async def cache_key(self, job):
        return None

    async def contains(self, item, /):
        return item in self.task.rev_jobs

    async def delete(self, job, /):
        """Deleting a job from the repository will cancel the corresponding task."""
        await self.task.cancel(job)


class InProcessMetadataRepository(MetadataRepository):
    """An incredibly simple metadata repository which stores all its values in a dict, and will let them vanish when
    the process terminates."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.data: Dict[str, Any] = data if data is not None else {}

    async def cache_key(self, job):
        return None

    def footprint(self):
        yield self

    def __getstate__(self):
        return id(self)

    def __repr__(self):
        return f"<{type(self).__name__}>"

    @job_getter
    async def info(self, job, /):
        return self.data.get(job)

    @job_getter
    async def dump(self, job, data, /):
        self.schema_validate(data)
        if not self.is_valid_job_id(job):
            raise KeyError(job)
        self.data[job] = data

    async def contains(self, item, /):
        return item in self.data

    async def delete(self, job, /):
        if job in self.data:
            del self.data[job]

    async def unfiltered_iter(self):
        for job in self.data:
            yield job


class InProcessBlobStream:
    """A stream returned from an `BlobRepository.open` call from `InProcessBlobRepository`.

    Do not construct this manually.
    """

    def __init__(self, repo: "InProcessBlobRepository", job: str):  # pylint: disable=missing-function-docstring
        super().__init__()
        self.repo = repo
        self.job = job
        self.data = io.BytesIO(repo.data.get(job, b""))

    def __getstate__(self):
        return id(self)

    async def read(self, n: int = -1, /) -> bytes:
        """Read up to ``n`` bytes from the stream."""
        return self.data.read(n)

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        return self.data.write(data)

    async def close(self) -> None:
        """Close and release the stream, syncing the data back to the repository."""
        self.repo.data[self.job] = self.data.getvalue()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class InProcessBlobRepository(BlobRepository):
    """An incredibly simple blob repository which stores all its values in a dict, and will let them vanish when the
    process terminates."""

    def __init__(self, data: Optional[Dict[str, bytes]] = None):
        super().__init__()
        self.data = data if data is not None else {}

    def footprint(self):
        yield self

    def __getstate__(self):
        return id(self)

    async def cache_key(self, job):
        return None

    def __repr__(self):
        return f"<{type(self).__name__}>"

    @overload
    async def open(self, job: str, mode: Literal["r"]) -> AReadText: ...

    @overload
    async def open(self, job: str, mode: Literal["w"]) -> AWriteText: ...

    @overload
    async def open(self, job: str, mode: Literal["rb"]) -> InProcessBlobStream: ...

    @overload
    async def open(self, job: str, mode: Literal["wb"]) -> InProcessBlobStream: ...

    @job_getter
    async def open(self, job, mode="r"):
        if not self.is_valid_job_id(job):
            raise KeyError(job)
        stream = InProcessBlobStream(self, job)
        if mode == "r":
            return AReadText(stream)
        elif mode == "w":
            return AWriteText(stream)
        else:
            return stream

    async def unfiltered_iter(self):
        for item in self.data:
            yield item

    async def contains(self, item, /):
        return item in self.data

    async def delete(self, job, /):
        del self.data[job]


class _Unknown:
    pass


class CacheInProcessMetadataRepository(MetadataRepository):
    """Caches all query results performed against a base repository.

    Be careful to flush occasionally!
    """

    def __init__(self, base: MetadataRepository):
        super().__init__()
        self.base = base
        self._unknown = _Unknown()
        self._cache: Dict[str, Any] = {}
        self._negative_cache: Set[str] = set()
        self._complete_keys = False
        self._complete_values = False

    def footprint(self):
        yield from self.base.footprint()

    def cache_flush(self, soft=False):
        self.base.cache_flush(soft=soft)
        self._cache = {}
        self._negative_cache = set()
        self._complete_keys = False
        self._complete_values = False

    async def cache_key(self, job):
        return await self.base.cache_key(job)

    async def info(self, job: str, /):
        # EXPERIMENT
        # if not self._complete_values:
        #    await self.info_all()
        # END EXPERIMENT
        result = self._cache.get(job, self._unknown)
        if result is self._unknown:
            result = await self.base.info(job)
            self._cache[job] = result
        return result

    async def info_all(self):
        if not self._complete_values:
            self._cache = await self.base.info_all()
            self._complete_values = True
            self._complete_keys = True
        # should we make it so that info raises an error on unknown keys?
        return dict(self._cache)

    async def contains(self, k: str, /) -> bool:
        if k in self._cache:
            return True
        if k in self._negative_cache:
            return False
        result = await self.base.contains(k)
        if result:
            self._cache[k] = self._unknown
        else:
            self._negative_cache.add(k)
        return result

    async def unfiltered_iter(self):
        if self._complete_keys:
            # do not yield in the middle of iterating a mutable dict
            keys = list(self._cache)
            for k in keys:
                yield k
        else:
            # optimization for any()
            single = next(iter(self._cache), None)
            if single is not None:
                yield single
            async for k in self.base:
                if k == single:
                    continue
                if k not in self._cache:
                    self._cache[k] = self._unknown
                yield k
            self._complete_keys = True

    async def delete(self, k, /):
        self._cache.pop(k, None)
        await self.base.delete(k)

    async def dump(self, k, v, /):
        await self.base.dump(k, v)
        self._cache[k] = v

    def __getstate__(self):
        return (self.base,)


class CompressedBlobRepository(BlobRepository):
    """A repository which exposes a normal blob interface but compresses all the data it stores under the hood."""

    def __init__(self, inner: BlobRepository):
        super().__init__()
        self.inner = inner

    @overload
    async def open(self, job, mode: Literal["r"]): ...

    @overload
    async def open(self, job, mode: Literal["w"]): ...

    @overload
    async def open(self, job, mode: Literal["rb"]): ...

    @overload
    async def open(self, job, mode: Literal["wb"]): ...

    @asyncasynccontextmanager
    async def open(self, job, mode="r"):
        """Open the given job's value as a stream for reading or writing, in text or binary mode."""
        if mode in ("r", "w"):
            raise NotImplementedError("Take your sensitive ass back to .decode()")
        if mode == "rb":
            # ULTIMATE HACKS
            proc = await asyncio.create_subprocess_exec(
                "gzip", "-d", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
            )
            assert proc.stdin is not None
            async with await self.inner.open(job, "rb") as fp, AWriteStreamDrainer(proc.stdin) as stdin:
                assert proc.stdout is not None
                task = asyncio.create_task(async_copyfile_close(fp, stdin))
                yield proc.stdout
            await task
            await proc.wait()
        elif mode == "wb":
            # ULTIMATE HACKS II
            proc = await asyncio.create_subprocess_exec(
                "gzip", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
            )
            assert proc.stdin is not None
            async with await self.inner.open(job, "wb") as fp:
                async with AWriteStreamDrainer(proc.stdin) as stdin:
                    assert proc.stdout is not None
                    task = asyncio.create_task(async_copyfile(proc.stdout, fp))
                    yield stdin
                await task
            await proc.wait()
        else:
            raise ValueError("Bad blob open mode: %s" % mode)

    def __getstate__(self):
        return (self.inner,)

    def footprint(self):
        yield self

    def cache_flush(self, soft=False):
        self.inner.cache_flush(soft=soft)

    async def cache_key(self, job):
        return await self.inner.cache_key(job)

    async def validate(self):
        await self.inner.validate()
        await super().validate()

    def delete(self, job, /):
        return self.inner.delete(job)

    def unfiltered_iter(self):
        return self.inner.unfiltered_iter()


class FilterBlobRepository(FilterRepository, BlobRepository):
    def __init__(
        self,
        base: BlobRepository,
        filt: Optional[Callable[[str], Awaitable[bool]]] = None,
        allow_deletes=False,
        extra_footprint: Optional[List[Repository]] = None,
    ):
        super().__init__(base, filt, allow_deletes, extra_footprint)

    @overload
    async def open(self, job: str, mode: Literal["r"]) -> AsyncContextManager[AReadTextProto]: ...

    @overload
    async def open(self, job: str, mode: Literal["w"]) -> AsyncContextManager[AWriteTextProto]: ...

    @overload
    async def open(self, job: str, mode: Literal["rb"]) -> AReadStreamManager: ...

    @overload
    async def open(self, job: str, mode: Literal["wb"]) -> AWriteStreamManager: ...

    base: BlobRepository

    async def open(self, job, mode: Union[Literal["r"], Literal["w"], Literal["rb"], Literal["wb"]] = "r"):
        """Open the given job's value as a stream for reading or writing, in text or binary mode."""
        return await self.base.open(job, mode)
