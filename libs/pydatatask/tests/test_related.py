import unittest

import pydatatask


class TestRelated(unittest.IsolatedAsyncioTestCase):
    async def test_related(self):
        translator = pydatatask.InProcessMetadataRepository({"456": "123"})

        base1 = pydatatask.InProcessBlobRepository({"123": b"asdf"})
        related1 = pydatatask.RelatedItemRepository(base1, translator)
        async with await related1.open("456", "rb") as fp:
            assert await fp.read() == b"asdf"
        await related1.delete("456")
        assert [x async for x in base1] == ["123"]
        assert [x async for x in related1] == ["456"]
        assert await related1.contains("456")
        assert not await related1.contains("lksfdlkfd")
        with self.assertRaises(LookupError):
            await related1.open("lkjfdslkj", "w")

        base2 = pydatatask.InProcessMetadataRepository({"123": "weh!"})
        related2 = pydatatask.RelatedItemRepository(base2, translator, allow_deletes=True, prefetch_lookup=False)
        assert await related2.info("456") == "weh!"

        await related2.delete("456")
        assert [x async for x in base2] == []
        await related2.delete("lsdlkjfj")

    async def test_allocated(self):
        source = pydatatask.InProcessMetadataRepository({"aa": 1})
        dest = pydatatask.InProcessMetadataRepository()
        done = pydatatask.InProcessMetadataRepository()

        @pydatatask.InProcessSyncTask("task", done)
        async def task(source, dest, **kwargs):
            await dest.dump(await source.info() + 1)

        task.link("source", source, kind=pydatatask.LinkKind.InputRepo)
        task.link("dest", dest, kind=pydatatask.LinkKind.OutputRepo, key="ALLOC", inhibits_start=True)

        pipeline = pydatatask.Pipeline([task], pydatatask.Session(), [])
        async with pipeline:
            assert await pipeline.update()
            assert not await pipeline.update()
            assert "aa" not in dest.data
            assert "aa" in done.data
            assert list(dest.data.values()) == [2]
            assert list(dest.data.keys()) == [str(task.derived_hash("aa", "dest"))]
            await done.delete("aa")
            assert not await pipeline.update()


if __name__ == "__main__":
    unittest.main()
