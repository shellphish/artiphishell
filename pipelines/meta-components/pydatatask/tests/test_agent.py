import asyncio.subprocess
import unittest

import aiohttp

from pydatatask.quota import LOCALHOST_QUOTA
import pydatatask


class TestAgent(unittest.IsolatedAsyncioTestCase):
    async def test_errors(self):
        manager = pydatatask.InProcessLocalLinuxManager(quota=LOCALHOST_QUOTA, app="test_agent")
        task = pydatatask.ProcessTask(
            "task",
            "",
            pydatatask.InProcessMetadataRepository(),
            executor=manager,
        )
        pipeline = pydatatask.Pipeline([task], pydatatask.Session())
        await pipeline.open()
        await manager.launch_agent(pipeline)
        headers = {"Cookie": "secret=" + pipeline.agent_secret}

        try:
            async with aiohttp.request(
                "GET", f"http://{pipeline.agent_hosts[None]}:{pipeline.agent_port}/ljksdfjksdfjlk", headers=headers
            ) as request:
                await request.read()
                assert request.status == 404
            async with aiohttp.request(
                "GET",
                f"http://{pipeline.agent_hosts[None]}:{pipeline.agent_port}/errors/ljksdfjksdfjlk",
                headers=headers,
            ) as request:
                text = await request.text()
                assert "seconds ago" in text
                assert "HTTPNotFound" in text
            async with aiohttp.request(
                "GET", f"http://{pipeline.agent_hosts[None]}:{pipeline.agent_port}/data/a/b/c", headers=headers
            ) as request:
                await request.read()
                assert request.status == 404
            async with aiohttp.request(
                "GET", f"http://{pipeline.agent_hosts[None]}:{pipeline.agent_port}/errors/data/a/b/c", headers=headers
            ) as request:
                text = await request.text()
                assert "seconds ago" in text
                assert "KeyError" in text

            with open("/tmp/scroingle", "w") as fp:
                fp.write("{holy fucking bingle")
            script = task.mk_repo_put("/tmp/scroingle", "done", "1")
            p = await asyncio.create_subprocess_shell(
                script, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            assert p.stdout is not None
            assert p.stderr is not None
            await p.wait()
            assert b"yaml.parser.ParserError" in await p.stderr.read()
        finally:
            await manager.teardown_agent()


if __name__ == "__main__":
    unittest.main()
