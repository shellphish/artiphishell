"""Tools for interacting with repositories in an extremely blunt way.

This is the only hammer you will ever need, if you are okay with that hammer kind of sucking.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple
from asyncio import Task, create_task, sleep
from datetime import timedelta
import logging
import time
import traceback

from aiohttp import web
from aiojobs.aiohttp import setup, spawn
import yaml

from pydatatask.utils import (
    AReadStreamBase,
    AWriteStreamBase,
    async_copyfile,
    safe_load,
)

from . import repository as repomodule
from .pipeline import Pipeline

l = logging.getLogger(__name__)


class _DeferredResponse:
    def __init__(self, request: web.Request):
        self.request = request
        self.response = web.StreamResponse()
        self.prepared = False

    async def write(self, data: bytes, /) -> int:
        """Write it."""
        if not self.prepared:
            await self.response.prepare(self.request)
            self.prepared = True
        await self.response.write(data)
        return len(data)

    async def write_eof(self):
        """Term it."""
        if not self.prepared:
            await self.response.prepare(self.request)
            self.prepared = True
        await self.response.write_eof()


def build_agent_app(
    pipeline: Pipeline, owns_pipeline: bool = False, flush_period: Optional[timedelta] = None
) -> web.Application:
    """Given a pipeline, generate an aiohttp web app to serve its repositories."""

    error_log: Dict[str, Tuple[float, str]] = {}

    @web.middleware
    async def authorize_middleware(request: web.Request, handler):
        if request.path != "/health" and request.cookies.get("secret", None) != pipeline.agent_secret:
            raise web.HTTPForbidden()
        return await handler(request)

    @web.middleware
    async def error_handling_middleware(request: web.Request, handler):
        try:
            return await handler(request)
        except Exception:
            error_log[request.path] = (time.time(), traceback.format_exc())
            raise

    app = web.Application(middlewares=[authorize_middleware, error_handling_middleware])
    setup(app)

    def parse(f):
        async def inner(request: web.Request) -> web.StreamResponse:
            try:
                repo = pipeline.tasks[request.match_info["task"]].links[request.match_info["link"]].repo
            except KeyError as e:
                raise web.HTTPNotFound() from e
            return await f(request, repo, request.match_info["job"])

        return inner

    @parse
    async def get(request: web.Request, repo: repomodule.Repository, job: str) -> web.StreamResponse:
        meta = request.query.getone("meta", None) == "1"
        subpath = request.query.getone("subpath", None)
        response = _DeferredResponse(request)
        if isinstance(repo, repomodule.FilesystemRepository):
            if meta:
                await cat_fs_meta(repo, job, response)
            elif subpath:
                await cat_fs_entry(repo, job, response, subpath)
            else:
                await cat_data(repo, job, response)
        else:
            await cat_data(repo, job, response)
        await response.write_eof()
        return response.response

    async def post(request: web.Request) -> web.StreamResponse:
        try:
            task = pipeline.tasks[request.match_info["task"]]
            link_str = request.match_info["link"]
            link = task.links[link_str]
            repo = link.repo
            job = request.match_info["job"]
            hostjob = request.query.getone("hostjob", None)
        except KeyError as e:
            raise web.HTTPNotFound() from e
        content = await task.instrument_dump(request.content, link_str, None, job, hostjob)
        await inject_data(repo, job, content, True)
        return web.Response(text=job)

    async def stream(request: web.Request) -> web.StreamResponse:
        try:
            task = pipeline.tasks[request.match_info["task"]]
            repo = task._repo_filtered(request.match_info["job"], request.match_info["link"])
        except KeyError as e:
            raise web.HTTPNotFound() from e
        response = web.StreamResponse()
        await response.prepare(request)
        async for result in repo:
            await response.write(result.encode() + b"\n")
        await response.write_eof()
        return response

    async def query(request: web.Request) -> web.StreamResponse:
        try:
            task = pipeline.tasks[request.match_info["task"]]
            query = task.queries[request.match_info["query"]]
        except KeyError as e:
            raise web.HTTPNotFound() from e
        try:
            params = safe_load(await request.read())
        except yaml.error.YAMLError as e:
            raise web.HTTPBadRequest() from e

        result = await query.execute(params)

        response = _DeferredResponse(request)
        await query.format_response(result, response)
        await response.write_eof()
        return response.response

    async def cokey_post(request: web.Request) -> web.StreamResponse:
        try:
            task = pipeline.tasks[request.match_info["task"]]
            link_str = request.match_info["link"]
            link = task.links[link_str]
            cokey_str = request.match_info["cokey"]
            repo = link.cokeyed[cokey_str]
            job = request.match_info["job"]
            hostjob = request.query.getone("hostjob", None)
        except KeyError as e:
            raise web.HTTPNotFound() from e
        content = await task.instrument_dump(request.content, link_str, cokey_str, job, hostjob)
        await inject_data(repo, job, content, True)
        return web.Response(text=job)

    async def errors(request: web.Request) -> web.StreamResponse:
        path = "/" + request.match_info["path"]
        if path not in error_log:
            return web.Response(text="No logged errors for this endpoint...")
        else:
            ts, err = error_log[path]
            return web.Response(text=f"Error from {time.time() - ts} seconds ago:\n{err}")

    async def health(request: web.Request) -> web.StreamResponse:
        return web.Response(text="OK")

    app.add_routes([web.get("/data/{task}/{link}/{job}", get), web.post("/data/{task}/{link}/{job}", post)])
    app.add_routes([web.get("/stream/{task}/{link}/{job}", stream)])
    app.add_routes([web.post("/query/{task}/{query}", query)])
    app.add_routes([web.post("/cokeydata/{task}/{link}/{cokey}/{job}", cokey_post)])
    app.add_routes([web.get("/errors/{path:.*}", errors)])
    app.add_routes([web.get("/health", health)])

    async def on_startup(_app: web.Application):
        await pipeline.open()

    async def on_shutdown(_app):
        await pipeline.close()

    if owns_pipeline:
        app.on_startup.append(on_startup)
        app.on_shutdown.append(on_shutdown)
    if flush_period is not None:
        cache_flush = web.AppKey("cache_flush", Task[None])

        async def background_flush():
            while True:
                pipeline.cache_flush()
                await sleep(flush_period.total_seconds())

        async def on_startup_flush(app):
            app[cache_flush] = create_task(background_flush())

        app.on_startup.append(on_startup_flush)
    return app


async def cat_data(item: repomodule.Repository, job: str, stream: AWriteStreamBase):
    """Copy one job of a repository to a stream."""
    if isinstance(item, repomodule.BlobRepository):
        async with await item.open(job, "rb") as fp:
            await async_copyfile(fp, stream)
    elif isinstance(item, repomodule.MetadataRepository):
        data_bytes = await item.info(job)
        data_str = yaml.safe_dump(data_bytes, None)
        if isinstance(data_str, str):
            await stream.write(data_str.encode())
        else:
            await stream.write(data_str)
    elif isinstance(item, repomodule.FilesystemRepository):
        await item.get_tarball(job, stream)
    else:
        raise TypeError(f"Unknown repository type: {type(item)=!r}, {item=!r}, {job=!r}")


async def cat_fs_meta(item: repomodule.FilesystemRepository, job: str, stream: AWriteStreamBase):
    """Copy the manifest of one job of a filesystem repository to a stream."""
    async for directory, dirs, files, links in item.walk(job):
        for name in dirs:
            await stream.write(f"{directory}/{name}/\n".encode())
        for name in files:
            await stream.write(f"{directory}/{name}\n".encode())
        for name in links:
            await stream.write(f"{directory}/{name}\n".encode())


async def cat_fs_entry(item: repomodule.FilesystemRepository, job: str, stream: AWriteStreamBase, path: str):
    """Copy one file of one job on a filesystem repository to a stream."""
    async with await item.open(job, path) as fp:
        await async_copyfile(fp, stream)


async def inject_data(item: repomodule.Repository, job: str, stream: AReadStreamBase, agent_warn: bool):
    """Ingest one job of a repository from a stream."""
    if agent_warn and await item.contains(job):
        l.warning(f"{item} already contains {job}")
        return

    if isinstance(item, repomodule.BlobRepository):
        async with await item.open(job, "wb") as fp:
            await async_copyfile(stream, fp)
    elif isinstance(item, repomodule.MetadataRepository):
        data = await stream.read()
        try:
            data_obj = safe_load(data)
        except yaml.YAMLError as e:
            # raise ValueError(e.args[0]) from e
            raise ValueError(f"Error parsing YAML: {e}, {e.args[0]} when parsing {item=!r} {job=!r}: {data=!r}") from e
        await item.dump(job, data_obj)
    elif isinstance(item, repomodule.FilesystemRepository):
        await item.dump_tarball(job, stream)
    else:
        raise TypeError(f"Unknown repository type: {type(item)=!r}, {item=!r}, {job=!r}")
