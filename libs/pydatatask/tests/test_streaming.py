from typing import cast
import asyncio
import getpass
import pathlib
import subprocess
import unittest

from pydatatask.cli.lock import TempAllocator
from pydatatask.repository.base import BlobRepository, MetadataRepository
from pydatatask.staging import Dispatcher, PipelineStaging
from pydatatask.task import ProcessTask

test_root = pathlib.Path(__file__).parent


class TestStreaming(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

    async def test_streaming(self):
        staging = PipelineStaging(test_root / "content" / "streaming_input" / "pipeline.yaml")
        allocated = staging.allocate(
            TempAllocator().allocate,
            Dispatcher("TempLinux", {"app": "test_streaming", "quota": {"cpu": 8, "mem": 1024**4}}),
        )
        pipeline = allocated.instantiate()
        # pipeline.settings(debug_trace=True)
        task = cast(ProcessTask, pipeline.tasks["task"])
        scope = cast(MetadataRepository, task.links["scope"].repo)
        live = task.links["live"].repo
        inputScope = cast(MetadataRepository, task.links["inputScope"].repo)
        inputBlob = cast(BlobRepository, task.links["input"].repo)
        outputBlob = cast(BlobRepository, task.links["output"].repo)
        outputMeta = cast(MetadataRepository, task.links["output"].cokeyed["meta"])
        logs = cast(BlobRepository, task.links["stdout"].repo)
        await task.manager.launch_agent(pipeline)
        try:
            async with pipeline:
                assert not await pipeline.update()
                await scope.dump("1", "hoo hoo hoo")
                assert await task.ready.contains("1")
                assert await pipeline.update()
                assert await live.contains("1")
                await inputScope.dump("100", {"target": 1})
                await inputScope.dump("101", {"target": 1})
                await inputScope.dump("102", {"target": 2})
                await inputScope.dump("103", {"target": 1})
                await inputScope.dump("104", {"target": 1})
                await inputBlob.blobdump("100", "hey")
                # await inputBlob.dump("101", "don't inject me")
                await inputBlob.blobdump("102", "hi")
                await inputBlob.blobdump("103", "done")
                await inputBlob.blobdump("104", "ho")
                await asyncio.sleep(0.5)
                assert await pipeline.update()
                i = 0
                while await pipeline.update():
                    await asyncio.sleep(0.5)
                    i += 1
                    if i > 100:
                        subprocess.run(f"find /tmp/pydatatask-{getpass.getuser()}", shell=True, check=True)
                        # subprocess.run(f"cat /tmp/pydatatask-{getpass.getuser()}/test_streaming/task/1/stdout", shell=True, check=True)
                        print((await logs.blobinfo("1")).decode())
                        subprocess.run(f"cat /tmp/pydatatask-{getpass.getuser()}/agent-stdout", shell=True, check=False)
                        assert False, "Pipeline timeout"
                # print((await logs.blobinfo("1")).decode())
                keys = {x async for x in outputBlob}
                allBlob = {await outputBlob.blobinfo(key) for key in keys}
                allMeta = {key: await outputMeta.info(key) for key in keys}
                assert allBlob == {b"hoo\nhey", b"hoo\ndone", b"hoo\nho"}
                assert len(allMeta) == 3
                assert all(v["job"] == 1 for v in allMeta.values())
                assert all(v["complex"]["thing_1"] is True for v in allMeta.values())
                assert {v["parent"] for v in allMeta.values()} == {100, 103, 104}
        finally:
            await task.manager.teardown_agent()


if __name__ == "__main__":
    unittest.main()
