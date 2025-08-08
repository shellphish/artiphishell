"""This module contains repositories for interacting with docker registries."""

from typing import Callable
import base64
import hashlib
import os

import aiohttp.client_exceptions
import docker_registry_client_async
import dxf

from .base import Repository, job_getter


class DockerRepository(Repository):
    """A docker repository is, well, an actual docker repository hosted in some registry somewhere.

    Keys translate to tags on this repository.
    """

    def __init__(
        self,
        registry: Callable[[], docker_registry_client_async.dockerregistryclientasync.DockerRegistryClientAsync],
        domain: str,
        repository: str,
    ):
        """
        :param registry: A callable returning a
                         `docker_registry_client_async <https://pypi.org/project/docker-registry-client-async/>`_
                         client object with appropriate authentication information.
        :param domain: The registry domain to connect to, e.g. ``index.docker.io``.
        :param repository: The repository to store images in within the domain, e.g. ``myname/myrepo``.
        """
        super().__init__()
        self._registry = registry
        self.domain = domain
        self.repository = repository

    def footprint(self):
        yield self

    def __getstate__(self):
        return (self.domain, self.repository)

    async def cache_key(self, job: str):
        return None

    @property
    def registry(self) -> docker_registry_client_async.dockerregistryclientasync.DockerRegistryClientAsync:
        """The ``docker_registry_client_async`` client object.

        If this is provided by an unopened session, raise an error.
        """
        return self._registry()

    async def unfiltered_iter(self):
        try:
            image = docker_registry_client_async.imagename.ImageName(self.repository, endpoint=self.domain)
            tags = (await self.registry.get_tags(image)).tags["tags"]
            if tags is None:
                return
            for tag in tags:
                yield tag
        except aiohttp.client_exceptions.ClientResponseError as e:
            if e.status != 404:
                raise

    def __repr__(self):
        return f"<dockerRepository {self.domain}/{self.repository}:*>"

    @job_getter
    async def info(self, job):
        """The info provided by a docker repository is a dict with two keys, "withdomain" and "withoutdomain". e.g.:

        .. code::

            { "withdomain": "docker.example.com/myname/myrepo:job", "withoutdomain": "myname/myrepo:job" }
        """
        return {
            "withdomain": f"{self.domain}/{self.repository}:{job}",
            "withoutdomain": f"{self.repository}:{job}",
        }

    def _dxf_auth(self, dxf_obj, response):
        # what a forking hack
        assert self.registry.credentials is not None
        for pattern, credentials in self.registry.credentials.items():
            if pattern.fullmatch(self.domain):
                result = credentials
                break
        else:
            raise PermissionError("Missing credentials for %s" % self.domain)
        if self.registry.ssl:
            username, password = base64.b64decode(result).decode().split(":")
            dxf_obj.authenticate(username, password, response)
        else:
            dxf_obj._headers = {"Authorization": "Basic " + result}

    async def delete(self, job, /):
        # if not await self.contains(job):
        #    return

        self._delete_inner(job)  # blocking! epic fail

    def _delete_inner(self, job):
        random_data = os.urandom(16)
        random_digest = "sha256:" + hashlib.sha256(random_data).hexdigest()

        d = dxf.DXF(
            host=self.domain,
            repo=self.repository,
            auth=self._dxf_auth,
            insecure=not self.registry.ssl,
        )
        # type stubs seem to be wrong
        d.push_blob(data=random_data, digest=random_digest)  # type: ignore
        d.set_alias(job, random_digest)
        d.del_alias(job)
