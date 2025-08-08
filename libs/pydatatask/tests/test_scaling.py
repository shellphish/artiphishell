from typing import cast
from decimal import Decimal
import asyncio
import pathlib
import unittest

from pydatatask.cli.lock import TempAllocator
from pydatatask.repository.base import BlobRepository, MetadataRepository
from pydatatask.staging import Dispatcher, PipelineStaging
from pydatatask.task import ProcessTask

test_root = pathlib.Path(__file__).parent


class TestScaling(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

    async def test_scaling(self):
        staging = PipelineStaging(test_root / "content" / "replication" / "pipeline.yaml")
        allocated = staging.allocate(
            TempAllocator().allocate,
            Dispatcher("TempLinux", {"app": "test_streaming", "quota": {"cpu": 8, "mem": 1024**4}}),
        )
        pipeline = allocated.instantiate()

        builder = cast(ProcessTask, pipeline.tasks["builder"])
        fuzzer_1 = cast(ProcessTask, pipeline.tasks["fuzzer_1"])
        fuzzer_2 = cast(ProcessTask, pipeline.tasks["fuzzer_2"])

        builder_repo = cast(MetadataRepository, builder.links["input"].repo)
        fuzzer_repo = cast(MetadataRepository, fuzzer_1.links["input"].repo)

        await builder.manager.launch_agent(pipeline)
        try:
            async with pipeline:
                # test plain priorities.
                # with a capacity of 7, we should spawn 1 builder and 1 fuzzer_2
                builder.manager.quota.cpu = Decimal(7)
                await builder_repo.dump("1", {})
                await fuzzer_repo.dump("1", {})
                await pipeline.update()
                assert set(await builder.manager.live(builder.name)) == {("1", 0)}
                assert set(await fuzzer_1.manager.live(fuzzer_1.name)) == set()
                assert set(await fuzzer_2.manager.live(fuzzer_2.name)) == {("1", 0)}

                # test replication and decay.
                # with a capacity of 24, fuzzer_1 should start to get scheduled more than fuzzer_2
                builder.manager.quota.cpu = Decimal(24)
                await pipeline.update()
                assert set(await builder.manager.live(builder.name)) == {("1", 0)}
                assert set(await fuzzer_1.manager.live(fuzzer_1.name)) == set(("1", n) for n in range(9))
                assert set(await fuzzer_2.manager.live(fuzzer_2.name)) == set(("1", n) for n in range(5))

                # test scale back
                # once we schedule another builder, some of the fuzzer jobs should be killed
                await builder_repo.dump("2", {})
                await pipeline.update()
                await asyncio.sleep(1)
                assert set(await builder.manager.live(builder.name)) == {("1", 0), ("2", 0)}
                assert set(await fuzzer_1.manager.live(fuzzer_1.name)) == set(("1", n) for n in range(6))
                assert set(await fuzzer_2.manager.live(fuzzer_2.name)) == set(("1", n) for n in range(4))
        finally:
            await builder.manager.teardown_agent()
