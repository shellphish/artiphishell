from typing import Optional
import asyncio
import base64
import gc
import json
import random
import shutil
import socket
import string
import unittest

import docker_registry_client_async
import dxf

import pydatatask


def rid(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class TestDockerHub(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)
        self._client = None

    @property
    def client(self):
        assert self._client is not None
        return self._client

    async def asyncSetUp(self):
        self._client = docker_registry_client_async.DockerRegistryClientAsync(
            client_session_kwargs={"connector_owner": True}, tcp_connector_kwargs={"family": socket.AF_INET}
        )

    async def test_docker_hub(self):
        repo = pydatatask.DockerRepository(lambda: self.client, "registry-1.docker.io", "library/registry")
        assert repr(repo)
        assert [x async for x in repo] != []

        with self.assertRaises(PermissionError):
            await repo.delete("latest")
        await self.client.add_credentials(credentials="asdf", endpoint="registry-1.docker.io")
        with self.assertRaises(dxf.exceptions.DXFUnauthorizedError):
            await repo.delete("latest")

    async def asyncTearDown(self):
        await self.client.close()
        gc.collect()


class TestDockerLocal(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)
        self._client: Optional[docker_registry_client_async.DockerRegistryClientAsync] = None
        docker_path = shutil.which("docker")
        self.docker_name = None
        self.test_id = rid()
        self._endpoint = None

        if docker_path is None:
            raise unittest.SkipTest("Docker is not installed")
        self.docker_path = docker_path

    @property
    def client(self):
        assert self._client is not None
        return self._client

    @property
    def endpoint(self):
        assert self._endpoint is not None
        return self._endpoint

    async def asyncSetUp(self):
        docker_registry_client_async.DockerRegistryClientAsync.DEFAULT_PROTOCOL = "http"
        self._client = docker_registry_client_async.DockerRegistryClientAsync(
            client_session_kwargs={"connector_owner": True}, tcp_connector_kwargs={"family": socket.AF_INET}, ssl=False
        )

        docker_name = f"pydatatask-test{self.test_id}"
        port = random.randrange(0x4000, 0x8000)
        p = await asyncio.create_subprocess_exec(
            self.docker_path,
            "run",
            "--rm",
            "--name",
            docker_name,
            "-e",
            "REGISTRY_STORAGE_DELETE_ENABLED=TRUE",
            "-e",
            f"REGISTRY_AUTH_HTPASSWD_REALM=http://localhost:{port}",
            "-e",
            "REGISTRY_AUTH_HTPASSWD_PATH=/htpasswd",
            "-d",
            "-p",
            f"{port}:5000",
            "library/registry:2",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await p.communicate()
        if await p.wait() != 0:
            raise unittest.SkipTest("Docker failed to launch registry:latest")

        await asyncio.sleep(1)

        p = await asyncio.create_subprocess_exec(
            self.docker_path,
            "logs",
            docker_name,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await p.communicate()
        if await p.wait() != 0:
            raise unittest.SkipTest("Docker failed to get logs for registry:latest")

        user = [line for line in stderr.split() if b"user=" in line][0].split(b"=")[1].decode()
        password = [line for line in stderr.split() if b"password=" in line][0].split(b"=")[1].decode().strip('"')

        self.docker_name = docker_name
        self._endpoint = f"localhost:{port}"
        await self.client.add_credentials(
            credentials=base64.b64encode(f"{user}:{password}".encode()).decode(), endpoint=self.endpoint
        )

    async def test_local_registry(self):
        repo = pydatatask.DockerRepository(lambda: self.client, self.endpoint, "foo/weh")
        info = await repo.info("bar")
        assert info["withdomain"] == f"{self.endpoint}/foo/weh:bar"
        assert info["withoutdomain"] == f"foo/weh:bar"
        image_name = docker_registry_client_async.ImageName("foo/weh", endpoint=self.endpoint, tag="bar")
        digest = docker_registry_client_async.FormattedSHA256.calculate(b"asdf")
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "text/plain",
                "size": 4,
                "digest": digest,
            },
            "layers": [],
        }

        x = await self.client.post_blob(image_name, data=b"asdf", digest=digest)
        await self.client.put_blob_upload(x.location, digest, data=b"asdf")
        await self.client.put_manifest(image_name, docker_registry_client_async.Manifest(json.dumps(manifest).encode()))

        assert [x async for x in repo] == ["bar"]
        await repo.delete("bar")
        assert [x async for x in repo] == []
        await repo.delete("bar")

    async def asyncTearDown(self):
        try:
            await self.client.close()
            gc.collect()
        finally:
            docker_registry_client_async.DockerRegistryClientAsync.DEFAULT_PROTOCOL = "https"

        if self.docker_name is not None:
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
