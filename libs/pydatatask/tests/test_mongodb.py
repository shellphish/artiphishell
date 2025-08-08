from typing import Optional
import asyncio
import os
import random
import shutil
import string
import unittest

import motor.motor_asyncio

import pydatatask


def rid(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class TestMongoDB(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self.docker_name = None
        self.docker_path = shutil.which("docker")
        self.mongo_url = os.getenv("PYDATATASK_TEST_MONGODB_URL")
        self.test_id = rid()
        self.client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
        self.database = "test-pydatatask-" + self.test_id

    async def asyncSetUp(self):
        if self.mongo_url is None:
            if self.docker_path is None:
                raise unittest.SkipTest("No mongodb endpoint configured and docker is not installed")
            port = random.randrange(0x4000, 0x8000)
            self.mongo_url = f"mongodb://root:root@localhost:{port}"
            p = await asyncio.create_subprocess_exec(
                self.docker_path,
                "run",
                "--rm",
                "--name",
                self.database,
                "-d",
                "-p",
                f"{port}:27017",
                "-e",
                "MONGO_INITDB_ROOT_USERNAME=root",
                "-e",
                "MONGO_INITDB_ROOT_PASSWORD=root",
                "mongo:latest",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await p.communicate()
            if await p.wait() != 0:
                raise unittest.SkipTest("No minio endpoint configured and docker failed to launch mongo:latest")
            self.docker_name = self.database
        self.client = motor.motor_asyncio.AsyncIOMotorClient(self.mongo_url)

        exc = None
        for _ in range(15):
            try:
                await self.client.get_database(self.database).test.find_one({})
            except Exception as e:
                exc = e
            else:
                break
            await asyncio.sleep(5)
        else:
            raise Exception("Can't communicate with mongodb") from exc

    async def test_mongo(self):
        assert self.client is not None
        client = self.client
        repo = pydatatask.MongoMetadataRepository(lambda: client.get_database(self.database), "test")
        assert repr(repo)
        await repo.dump("foo", {"weh": 1})
        assert len([x async for x in repo]) == 1
        assert (await repo.info("foo"))["weh"] == 1
        thingy = await self.client.get_database(self.database).test.find_one({"_id": "foo"})
        assert thingy is not None
        assert thingy["weh"] == 1
        assert await repo.contains("foo")
        assert not await repo.contains("bar")
        all_things = await repo.info_all()
        assert len(all_things) == 1
        assert "foo" in all_things
        assert all_things["foo"]["weh"] == 1

        await repo.delete("foo")
        assert await repo.info("foo") == {}
        assert len([x async for x in repo]) == 0

    async def test_fallback(self):
        assert self.client is not None
        client = self.client
        repo = pydatatask.MongoMetadataRepository(lambda: client.get_database(self.database), "test2")
        try:
            await repo.dump("1", 1)
        except:
            pass
        else:
            assert False, "Shouldn't be able to store a raw int"

        fallback = pydatatask.InProcessMetadataRepository()
        repo2 = pydatatask.FallbackMetadataRepository(repo, fallback)

        await repo2.dump("1", 1)
        assert (await repo2.info("1")) == 1

        await repo2.dump("2", {"asdf": "qwer"})
        assert await repo2.contains("2")
        assert not await fallback.contains("2")

        await repo2.dump("3", {"asdf": "A" * (17 * 1024 * 1024)})
        assert await repo2.contains("3")
        assert not await repo.contains("3")

    async def asyncTearDown(self):
        if self.client is not None:
            await self.client.drop_database(self.database)

        if self.docker_name is not None and self.docker_path is not None:
            p = await asyncio.create_subprocess_exec(
                self.docker_path,
                "kill",
                self.docker_name,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await p.communicate()


if __name__ == "__main__":
    unittest.main()
