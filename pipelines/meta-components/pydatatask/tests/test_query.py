from typing import cast
import pathlib
import unittest

from pydatatask.cli.lock import TempAllocator
from pydatatask.repository.base import MetadataRepository
from pydatatask.staging import Dispatcher, PipelineStaging
from pydatatask.task import ProcessTask

test_root = pathlib.Path(__file__).parent


class TestQuery(unittest.IsolatedAsyncioTestCase):
    async def test_query(self):
        staging = PipelineStaging(test_root / "content" / "query" / "pipeline.yaml")
        allocated = staging.allocate(
            TempAllocator().allocate,
            Dispatcher("TempLinux", {"app": "test_streaming", "quota": {"cpu": 8, "mem": 1024**4}}),
        )
        pipeline = allocated.instantiate()
        # pipeline.settings(debug_trace=True)
        task0 = cast(ProcessTask, pipeline.tasks["task0"])
        task1 = cast(ProcessTask, pipeline.tasks["task1"])
        inputs = cast(MetadataRepository, task0.links["output"].repo)
        filtered = cast(MetadataRepository, task1.links["input"].repo)

        async with pipeline:
            await inputs.dump("1", {"works": False, "is": "one"})
            await inputs.dump("2", {"works": True, "is": "two"})
            assert await filtered.info_all() == {"1": {"works": False, "is": "one"}}


if __name__ == "__main__":
    unittest.main()
