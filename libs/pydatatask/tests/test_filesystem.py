import tempfile
import unittest

import aiofiles.os
import aioshutil

import pydatatask


class TestFilesystem(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self._dir = None

    async def asyncSetUp(self):
        self._dir = tempfile.mkdtemp()

    @property
    def dir(self):
        assert self._dir is not None
        return self._dir

    async def test_filesystem(self):
        assert self.dir is not None
        repo = pydatatask.FileRepository(self.dir, extension=".txt")
        assert repr(repo)
        await repo.validate()

        async with await repo.open("foo", "w") as fp:
            await fp.write("hello world")
        async with aiofiles.open(self.dir + "/foo.yaml", "w") as fp:
            await fp.write("# lol\n")
        async with aiofiles.open(self.dir + "/foo.txt", "rb") as fp:
            assert await fp.read() == b"hello world"
        async with await repo.open("foo", "rb") as fp:
            assert await fp.read() == b"hello world"
        assert [x async for x in repo] == ["foo"]
        assert str(repo.fullpath("bar")) == self.dir + "/bar.txt"
        await repo.delete("foo")
        await repo.delete("bar")
        assert [x async for x in repo] == []

    async def test_case_insensitivity(self):
        assert self.dir is not None
        repo = pydatatask.FileRepository(self.dir, extension=".txt", case_insensitive=True)
        await repo.validate()

        async with aiofiles.open(self.dir + "/foo.txt", "w") as fp:
            await fp.write("# lol\n")
        async with aiofiles.open(self.dir + "/bar.TXT", "w") as fp:
            await fp.write("# lol\n")
        assert {x async for x in repo} == {"foo", "bar"}

    async def test_directory(self):
        repo = pydatatask.DirectoryRepository(self.dir, discard_empty=False)
        repo_noempty = pydatatask.DirectoryRepository(self.dir, discard_empty=True)

        await repo.mkdir("foo")
        await repo.mkdir("foo")
        assert [x async for x in repo] == ["foo"]
        assert [x async for x in repo_noempty] == []
        assert await repo.contains("foo")
        assert not await repo.contains("bar")
        assert not await repo_noempty.contains("foo")
        assert not await repo_noempty.contains("bar")
        await aiofiles.os.mkdir(repo_noempty.fullpath("foo") / "weh")
        assert await repo_noempty.contains("foo")
        assert [x async for x in repo_noempty] == ["foo"]

        await repo.delete("foo")
        assert [x async for x in repo] == []

    async def test_yaml(self):
        assert self.dir is not None
        repo = pydatatask.YamlMetadataFileRepository(self.dir)

        await repo.dump("foo", {"weh": 1})
        assert await repo.info("foo") == {"weh": 1}

    async def asyncTearDown(self):
        if self.dir is not None:
            await aioshutil.rmtree(self.dir)


if __name__ == "__main__":
    unittest.main()
