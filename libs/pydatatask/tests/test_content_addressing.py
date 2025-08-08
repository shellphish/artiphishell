import io
import tarfile
import tempfile
import unittest

from aiofiles.threadpool import wrap
import aioshutil

import pydatatask


class TestFilesystem(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self.meta_dir = self.blob_dir = self.repo = None

    async def asyncSetUp(self):
        self.meta_dir = tempfile.mkdtemp()
        self.blob_dir = tempfile.mkdtemp()
        meta = pydatatask.YamlMetadataFileRepository(self.meta_dir)
        blob = pydatatask.FileRepository(self.blob_dir)
        self.repo = pydatatask.ContentAddressedBlobRepository(blob, meta)

    async def test_content_addressing(self):
        assert self.repo is not None
        buf = io.BytesIO()

        tar = tarfile.open(fileobj=buf, mode="w:")
        info = tarfile.TarInfo("letters/a")
        info.size = 1
        info.mode = 123
        tar.addfile(info, io.BytesIO(b"A"))
        info = tarfile.TarInfo("letters/b")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"B"))
        info = tarfile.TarInfo("secrets/1")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"B"))
        info = tarfile.TarInfo("letters/A")
        info.type = tarfile.SYMTYPE
        info.linkname = "a"
        tar.addfile(info)
        info = tarfile.TarInfo("letters/B")
        info.type = tarfile.SYMTYPE
        info.linkname = "../secrets/1"
        tar.addfile(info)
        tar.close()

        buf.seek(0)
        await self.repo.dump_tarball("1", wrap(buf))
        assert (await self.repo.meta.info("1")) is not None

        files = [f async for f in self.repo.blobs]
        assert len(files) == 2
        async with await self.repo.open("1", "letters/B") as fp:
            data = await fp.read()
            assert b"B" == data
        assert await self.repo.get_mode("1", "letters/a") == 123

    async def asyncTearDown(self):
        pass
        # if self.meta_dir is not None:
        #    await aioshutil.rmtree(self.meta_dir)
        # if self.blob_dir is not None:
        #    await aioshutil.rmtree(self.blob_dir)
