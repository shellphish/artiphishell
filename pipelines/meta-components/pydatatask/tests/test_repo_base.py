import logging
import unittest

import pydatatask


class TestRepoBase(unittest.IsolatedAsyncioTestCase):
    async def test_derived(self):
        class DerivedRepository(pydatatask.Repository):
            def __getstate__(self):
                return "foo"

            def footprint(self):
                yield self

            async def unfiltered_iter(self):
                yield "foo"
                yield " "

            async def delete(self, job):
                pass

            async def info(self, job):
                return None

            async def cache_key(self, job):
                return None

        repo = DerivedRepository()

        with self.assertLogs("pydatatask.repository") as cl:
            assert not await repo.contains("weh")
            assert await repo.contains("foo")
        assert len(cl.records) == 1
        for x in cl.records:
            assert "valid job" in x.message

    async def test_map(self):
        class DerivedRepository(pydatatask.MetadataRepository):
            def __getstate__(self):
                return "foo"

            def footprint(self):
                yield self

            async def unfiltered_iter(self):
                yield "foo"
                yield "bar"

            async def info(self, job):
                return "info"

            async def delete(self, key):
                logging.root.debug("deleting %s", key)

            async def dump(self, job, data):
                raise NotImplementedError

            async def cache_key(self, job):
                return None

        repo = DerivedRepository()

        async def mapper(job, info):
            return info.upper()

        async def filter(job):
            return job == "foo"

        mapped = repo.map(mapper, [], filt=filter, allow_deletes=True)

        assert [x async for x in mapped] == ["foo"]
        assert await mapped.contains("foo")
        assert not await mapped.contains("bar")
        assert not await mapped.contains("weh")

        with self.assertLogs(logging.root, "DEBUG") as cl:
            await mapped.delete("foo")
            await mapped.delete("bar")
            await mapped.delete("weh")
        assert [record.message for record in cl.records] == ["deleting foo", "deleting bar", "deleting weh"]


if __name__ == "__main__":
    unittest.main()
