from pathlib import Path
import asyncio
import base64
import random
import shutil
import string
import unittest

import aioshutil
import asyncssh

from pydatatask.executor.proc_manager import InProcessLocalLinuxManager
from pydatatask.host import Host, HostOS
from pydatatask.task import LinkKind
import pydatatask


def rid(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class TestLocalProcess(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self.app = f"test-{rid()}"
        self.dir = Path(f"/tmp/pydatatask-{self.app}")
        self.n = 50
        self.agent_port = random.randrange(0x4000, 0x8000)

    async def test_local_process(self):
        session = pydatatask.Session()
        quota = pydatatask.Quota.parse(1, 1)

        repo_input = pydatatask.FileRepository(self.dir / "input")
        await repo_input.validate()
        for i in range(self.n):
            async with await repo_input.open(str(i), "w") as fp:
                await fp.write(str(i))
        repo_stdout = pydatatask.InProcessBlobRepository()
        repo_done = pydatatask.InProcessMetadataRepository()

        template = """\
#!/bin/sh
echo weh | cat {{input}} -
echo bye >&2
        """

        manager = InProcessLocalLinuxManager(quota, app="tests")
        task = pydatatask.ProcessTask(
            "task",
            template,
            done=repo_done,
            executor=manager,
            job_quota=pydatatask.Quota.parse("100m", "100m"),
            environ={},
            stdin=None,
            stdout=repo_stdout,
            stderr=pydatatask.STDOUT,
        )
        task.link("input", repo_input, LinkKind.InputFilepath)

        pipeline = pydatatask.Pipeline([task], session, agent_port=self.agent_port)
        await manager.launch_agent(pipeline)

        try:
            async with pipeline:
                await pydatatask.run(pipeline, False, False, 120)
        finally:
            await manager.teardown_agent()

        assert len(repo_stdout.data) == self.n
        assert len(repo_done.data) == self.n

        for i in range(self.n):
            assert repo_stdout.data[str(i)] == f"{i}weh\nbye\nShutting down now\n".encode()
            assert repo_done.data[str(i)]["exit_code"] == 0

    async def asyncTearDown(self):
        await aioshutil.rmtree(self.dir, ignore_errors=True)


class TestSSHProcess(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self.docker_name = None
        self.docker_path = shutil.which("docker")
        self.test_id = rid()
        self.port = None
        self.n = 50

    async def asyncSetUp(self):
        if self.docker_path is None:
            raise unittest.SkipTest("Docker is not installed")
        self.port = random.randrange(0x4000, 0x8000)
        name = f"pydatatask-test-{self.test_id}"
        p = await asyncio.create_subprocess_exec(
            self.docker_path,
            "run",
            "--rm",
            "--name",
            name,
            "-d",
            "-p",
            f"{self.port}:2222",
            "-e",
            "USER_NAME=weh",
            "-e",
            "USER_PASSWORD=weh",
            "-e",
            "PASSWORD_ACCESS=true",
            "linuxserver/openssh-server:version-9.1_p1-r2",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await p.communicate()
        if await p.wait() != 0:
            raise unittest.SkipTest("docker failed to launch linuxserver/openssh-server:version-9.1_p1-r2")
        self.docker_name = name
        await asyncio.sleep(5)

    async def test_ssh_process(self):
        session = pydatatask.Session()

        @session.ephemeral
        async def ssh():
            async with asyncssh.connect(
                "localhost",
                port=self.port,
                username="weh",
                password="weh",
                known_hosts=None,
                client_keys=None,
            ) as s:
                yield s

        quota = pydatatask.Quota.parse(1, 1)
        procman = pydatatask.SSHLinuxManager(quota, self.test_id, ssh, Host("remote", HostOS.Linux))

        repo_stdin = pydatatask.InProcessBlobRepository({str(i): str(i).encode() for i in range(self.n)})
        repo_stdout = pydatatask.InProcessBlobRepository()
        repo_stderr = pydatatask.InProcessBlobRepository()
        repo_done = pydatatask.InProcessMetadataRepository()

        template = """\
#!/bin/sh
echo 'hello world!' >&2
echo "The message of day {{job}} is $(base64). That's pretty great!"
echo 'goodbye world!' >&2
        """

        task = pydatatask.ProcessTask(
            "task",
            template,
            repo_done,
            procman,
            job_quota=pydatatask.Quota.parse("100m", "100m"),
            environ={},
            stdin=repo_stdin,
            stdout=repo_stdout,
            stderr=repo_stderr,
        )

        pipeline = pydatatask.Pipeline([task], session)

        async with pipeline:
            await pydatatask.run(pipeline, False, False, 120)

        assert len(repo_stdin.data) == self.n
        assert len(repo_stdout.data) == self.n
        assert len(repo_stderr.data) == self.n
        assert len(repo_done.data) == self.n

        for i in range(self.n):
            assert repo_stderr.data[str(i)] == "hello world!\ngoodbye world!\n".encode()
            assert (
                repo_stdout.data[str(i)]
                == f"The message of day {i} is {base64.b64encode(repo_stdin.data[str(i)]).decode()}. That's pretty great!\nShutting down now\n".encode()
            )
            assert repo_done.data[str(i)]["exit_code"] == 0

    async def asyncTearDown(self):
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
