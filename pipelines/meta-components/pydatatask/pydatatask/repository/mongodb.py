"""This module contains repositories for interacting with MongoDB as a data store."""

from typing import Any, Callable, Dict, Optional, Union
import logging

from bson import Int64, errors
import motor.core
import motor.motor_asyncio

from .base import MetadataRepository, job_getter

l = logging.getLogger(__name__)


class MongoMetadataRepository(MetadataRepository):
    """A metadata repository using a mongodb collection as the backing store."""

    def __init__(
        self,
        database: Callable[[], Union[motor.core.AgnosticCollection, motor.core.AgnosticDatabase]],
        collection: str,
    ):
        """
        :param collection: A callable returning a motor async collection.
        :param subcollection: Optional: the name of a subcollection within the collection in which to store data.
        """
        super().__init__()
        self._database = database
        self._collection = collection

    def footprint(self):
        yield self

    def __getstate__(self):
        return (self.collection,)  # uhhhhhh not enough!

    def __repr__(self):
        return f"<{type(self).__name__} {self._collection}>"

    @property
    def collection(self) -> motor.core.AgnosticCollection:
        """The motor async collection data will be stored in.

        If this is provided by an unopened session, raise an error.
        """
        return self._database()[self._collection]

    async def contains(self, item, /):
        return await self.collection.count_documents({"_id": item}) != 0

    async def delete(self, job, /):
        await self.collection.delete_one({"_id": job})

    async def unfiltered_iter(self):
        async for x in self.collection.find({}, projection=["_id"]):
            yield x["_id"]

    async def cache_key(self, job):
        return f"mongo:{self._collection}/{job}"

    @job_getter
    async def info(self, job, /):
        """The info of a mongo metadata repository is the literal value stored in the repository with identifier
        ``job``."""
        # WHY does mypy think this doesn't work
        result: Optional[Any] = await self.collection.find_one({"_id": job})  # type: ignore[func-returns-value]
        if result is None:
            return {}
        return self._fix_bson(result, root=True)

    async def info_all(self) -> Dict[str, Any]:
        return {entry["_id"]: self._fix_bson(entry, root=True) async for entry in self.collection.find({})}

    @classmethod
    def _fix_bson(cls, thing, root=False):
        if isinstance(thing, dict):
            if root:
                thing.pop("_id")
            for k, v in thing.items():
                thing[k] = cls._fix_bson(v)
        elif isinstance(thing, list):
            for i, v in enumerate(thing):
                thing[i] = cls._fix_bson(v)
        elif isinstance(thing, Int64):
            return int(thing)
        return thing

    @job_getter
    async def dump(self, job, data, /):
        self.schema_validate(data)
        if not self.is_valid_job_id(job):
            raise KeyError(job)
        try:
            await self.collection.replace_one({"_id": job}, data, upsert=True)
        except (TypeError, errors.BSONError) as e:
            raise Exception(f"Failed to dump a document to mongodb. The document is:\n{data}") from e


class FallbackMetadataRepository(MetadataRepository):
    def __init__(
        self,
        base: MetadataRepository,
        fallback: MetadataRepository,
    ):
        self.base = base
        self.fallback = fallback
        super().__init__()

    async def cache_key(self, job):
        return await self.base.cache_key(job)

    async def unfiltered_iter(self):
        async for x in self.base:
            yield x
        async for x in self.fallback:
            yield x

    async def contains(self, job):
        return (await self.base.contains(job)) or (await self.fallback.contains(job))

    async def info(self, job):
        if await self.base.contains(job):
            return await self.base.info(job)
        return await self.fallback.info(job)

    async def info_all(self):
        result = await self.base.info_all()
        result.update(await self.fallback.info_all())
        return result

    async def dump(self, job, data):
        try:
            await self.base.dump(job, data)
        except Exception:
            await self.fallback.dump(job, data)
            await self.base.delete(job)
        else:
            await self.fallback.delete(job)

    async def delete(self, job):
        await self.base.delete(job)
        await self.fallback.delete(job)

    def cache_flush(self):
        self.base.cache_flush()
        self.fallback.cache_flush()

    def footprint(self):
        yield self  # me when I lie

    def __getstate__(self):
        return (self.base, self.fallback)
