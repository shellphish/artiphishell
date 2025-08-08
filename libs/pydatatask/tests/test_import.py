from typing import Optional
import asyncio
import os
import pathlib
import unittest

import aioshutil

test_root = pathlib.Path(__file__).parent


class TestImport(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

    @staticmethod
    async def cmd(shell: str, check: Optional[bool] = True):
        p = await asyncio.create_subprocess_shell(shell)
        result = await p.wait()
        if check is not None:
            assert (result == 0) == check, shell

    async def asyncSetUp(self):
        os.chdir(test_root / "content" / "import")
        await self.cmd("pdl --repo-local")
        await self.cmd("PIPELINE_YAML=1.yaml pdl --repo-local")
        await self.cmd("PIPELINE_YAML=2.yaml pdl --repo-local")

    async def test_backup(self):
        await self.cmd("echo 'qwer: 1' | pd inject task_1.output 1")
        await self.cmd("echo 'eeee: 1' | pd inject task_2.output 1")
        await self.cmd("cat test.tar.gz | pd inject task_2.extra 1")
        await self.cmd("pd backup --all backup")
        await self.cmd("PIPELINE_YAML=1.yaml pd restore --all backup")
        await self.cmd("PIPELINE_YAML=1.yaml pd status | grep 'task_1.output 1'")
        await self.cmd("PIPELINE_YAML=1.yaml pd status | grep 'task_1.extra 1'")
        await self.cmd("PIPELINE_YAML=2.yaml pd restore --all backup")
        await self.cmd("PIPELINE_YAML=2.yaml pd status | grep 'task_2.input 1'")
        await self.cmd("PIPELINE_YAML=2.yaml pd status | grep 'task_2.extra 1'")

    async def asyncTearDown(self):
        await self.cmd("pdl --unlock")
        await self.cmd("PIPELINE_YAML=1.yaml pdl --unlock")
        await self.cmd("PIPELINE_YAML=2.yaml pdl --unlock")
        await aioshutil.rmtree("backup")


if __name__ == "__main__":
    unittest.main()
