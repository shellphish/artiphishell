from concurrent.futures import ThreadPoolExecutor
import unittest

from pydatatask.quota import LOCALHOST_QUOTA, Quota
import pydatatask


class TestExecutor(unittest.IsolatedAsyncioTestCase):
    async def test_executor(self):
        session = pydatatask.Session()
        repo0 = pydatatask.InProcessMetadataRepository({"foo": "weh"})
        repo1 = pydatatask.InProcessMetadataRepository()
        repo2 = pydatatask.InProcessMetadataRepository()
        phase0_done = pydatatask.InProcessMetadataRepository()
        phase1_done = pydatatask.InProcessMetadataRepository()

        executor = ThreadPoolExecutor(1)

        @pydatatask.ExecutorTask("phase0", executor, Quota.parse(1, 1), LOCALHOST_QUOTA, phase0_done)
        async def phase0(
            repo_zero,
            repo_one,
            **kwargs,
        ):
            print(repo_zero)
            await repo_one.dump(await repo_zero.info() + "!")

        @pydatatask.ExecutorTask("phase1", executor, Quota.parse(1, 1), LOCALHOST_QUOTA, phase1_done)
        async def phase1(repo_one, repo_two, **kwargs):
            await repo_two.dump(await repo_one.info() + "?")

        phase0.link("repo_zero", repo0, kind=pydatatask.LinkKind.InputRepo)
        phase0.link("repo_one", repo1, kind=pydatatask.LinkKind.OutputRepo)

        phase1.link("repo_one", repo1, kind=pydatatask.LinkKind.InputRepo)
        phase1.link("repo_two", repo2, pydatatask.LinkKind.OutputRepo)

        pipeline = pydatatask.Pipeline([phase0, phase1], session)

        async with pipeline:
            await pydatatask.run(pipeline, forever=False, launch_once=False, timeout=120)
            await pydatatask.launch(
                pipeline,
                "phase0",
                "bar",
                sync=True,
                meta=True,
                force=True,
            )

        assert repo2.data["foo"] == "weh!?"
        assert "exception" in phase0_done.data["bar"]


if __name__ == "__main__":
    unittest.main()
