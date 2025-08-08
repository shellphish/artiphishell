"""High-level interfaces for accessing query results in the form of repositories."""

from typing import (
    Any,
    AsyncContextManager,
    AsyncIterator,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
    overload,
)
from pathlib import Path
import re

from pydatatask.repository import (
    BlobRepository,
    FilesystemRepository,
    MetadataRepository,
    Repository,
)
from pydatatask.repository.filesystem import FilesystemType
from pydatatask.utils import (
    AReadStreamBase,
    AReadStreamManager,
    AReadTextProto,
    AWriteStreamBase,
    AWriteStreamManager,
    AWriteTextProto,
)

from .parser import QueryValueType
from .query import Query


class QueryRepository(Repository):
    """A QueryRepository is a repository which uses a query expression to generate the keys and values available."""

    def __init__(
        self,
        query: str,
        getters: Optional[Dict[str, QueryValueType]] = None,
        repos: Optional[Dict[str, Repository]] = None,
        jq: Optional[Dict[str, str]] = None,
    ):
        super().__init__()
        self.query = Query(QueryValueType.Repository, query, {}, getters or {}, repos or {}, jq or {})
        self._cached: Optional[Repository] = None
        self._repo_in_query_str = None
        if self.query.query:
            self._repo_in_query_str = next((
                repo
                for reponame, repo in self.query.repos.items()
                if re.search("\\b" + reponame + "\\b", self.query.query)),
                None
            )


    def footprint(self):
        # HACK LMAO
        if self._repo_in_query_str:
            yield from self._repo_in_query_str.footprint()
        else:
            for reponame, repo in self.query.repos.items():
                if re.search("\\b" + reponame + "\\b", self.query.query):
                    yield from repo.footprint()

    def cache_flush(self, soft=False):
        self._cached = None
        # HACK LMAO
        if self._repo_in_query_str:
            self._repo_in_query_str.cache_flush(soft=soft)
        else:
            for reponame, repo in self.query.repos.items():
                if re.search("\\b" + reponame + "\\b", self.query.query):
                    repo.cache_flush(soft=soft)

    async def _resolve(self) -> Repository:
        if self._cached is None:
            repo = await self.query.execute({})
            assert repo.type == QueryValueType.Repository
            assert repo.repo_value is not None
            self._cached = repo.repo_value
        return self._cached

    async def contains(self, key: str, /):
        return await (await self._resolve()).contains(key)

    async def unfiltered_iter(self):
        async for key in await self._resolve():
            yield key

    async def delete(self, key: str, /):
        return await (await self._resolve()).delete(key)

    def __getstate__(self):
        return (self.query,)

    async def cache_key(self, job):
        return await (await self._resolve()).cache_key(job)


class QueryMetadataRepository(QueryRepository, MetadataRepository):
    """A QueryMetadataRepository is just a QueryRepository but additionally a MetadataRepository."""

    async def _resolve(self) -> MetadataRepository:
        result = await super()._resolve()
        assert isinstance(result, MetadataRepository)
        return result

    async def info(self, key: str, /):
        return await (await self._resolve()).info(key)

    async def info_all(self):
        return await (await self._resolve()).info_all()

    async def dump(self, key: str, data: Any, /):
        return await (await self._resolve()).dump(key, data)


class QueryBlobRepository(QueryRepository, BlobRepository):
    """A QueryBlobRepository is just a QueryRepository but additionally a BlobRepository."""

    async def _resolve(self) -> BlobRepository:
        result = await super()._resolve()
        assert isinstance(result, BlobRepository)
        return result

    @overload
    async def open(self, job: str, mode: Literal["r"]) -> AsyncContextManager[AReadTextProto]: ...

    @overload
    async def open(self, job: str, mode: Literal["w"]) -> AsyncContextManager[AWriteTextProto]: ...

    @overload
    async def open(self, job: str, mode: Literal["rb"]) -> AReadStreamManager: ...

    @overload
    async def open(self, job: str, mode: Literal["wb"]) -> AWriteStreamManager: ...

    async def open(self, job, mode: Union[Literal["r"], Literal["w"], Literal["rb"], Literal["wb"]] = "r"):
        """Open the given job's value as a stream for reading or writing, in text or binary mode."""
        guy = await self._resolve()
        return await guy.open(job, mode)


class QueryFilesystemRepository(QueryRepository, FilesystemRepository):
    """A QueryMetadataRepository is just a QueryRepository but additionally a FilesystemRepository."""

    async def _resolve(self) -> FilesystemRepository:
        result = await super()._resolve()
        assert isinstance(result, FilesystemRepository)
        return result

    async def dump(self, job: str):
        thing = (await self._resolve()).dump(job)
        try:
            while True:
                entry = yield
                await thing.asend(entry)
        except StopAsyncIteration:
            pass

    async def get_mode(self, job: str, path: str) -> Optional[int]:
        return await (await self._resolve()).get_mode(job, path)

    async def get_regular_meta(self, job: str, path: str) -> Tuple[int, Optional[str]]:
        return await (await self._resolve()).get_regular_meta(job, path)

    async def get_type(self, job: str, path: str) -> Optional[FilesystemType]:
        return await (await self._resolve()).get_type(job, path)

    async def open(self, job: str, path: Union[str, Path]) -> AsyncContextManager[AReadStreamBase]:
        return await (await self._resolve()).open(job, path)

    async def readlink(self, job: str, path: str) -> str:
        return await (await self._resolve()).readlink(job, path)

    async def walk(self, job: str) -> AsyncIterator[Tuple[str, List[str], List[str], List[str]]]:
        async for a, b, c, d in (await self._resolve()).walk(job):
            yield a, b, c, d

    async def iterdir(self, job, path):
        async for a in (await self._resolve()).iterdir(job, path):
            yield a

    async def dump_tarball(self, job: str, stream: AReadStreamBase) -> None:
        return await (await self._resolve()).dump_tarball(job, stream)

    async def get_tarball(self, job: str, dest: AWriteStreamBase) -> None:
        return await (await self._resolve()).get_tarball(job, dest)
