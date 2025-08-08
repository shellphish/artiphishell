"""Tools for interacting with repositories in an extremely blunt way.

This is the only hammer you will ever need, if you are okay with that hammer kind of sucking.
"""

from __future__ import annotations

import asyncio
from typing import Dict, Optional, Tuple
from asyncio import Task, create_task, sleep
from datetime import timedelta
import logging
import time
import traceback
import subprocess
import os
import sys
import json
import requests
import shutil

from aiohttp import web
from aiojobs.aiohttp import setup, spawn
import orjson
import yaml

try:
    from filelock import FileLock, Timeout
    from contextlib import contextmanager

    @contextmanager
    def optional_filelock(lock_path, timeout=10, max_retries=3, retry_delay=0.1):
        """
        best-effort file lock. tries to acquire, but continues anyway if it can't.
        
        useful for resource optimizations where locking is preferred but not required.
        """
        retries = 0
        lock = FileLock(lock_path, timeout=timeout)
        
        while retries < max_retries:
            try:
                with lock:
                    yield True  # indicates we got the lock
                    return
            except Timeout:
                retries += 1
                if retries >= max_retries:
                    break
                
                # attempt to remove potentially stale lock
                try:
                    os.remove(lock_path)
                    time.sleep(retry_delay)
                except:
                    pass
        
        # couldn't get lock, but continue anyway
        yield False  # indicates we're proceeding without lock
except ImportError:
    def optional_filelock(lock_path, timeout=10, max_retries=3, retry_delay=0.1):
        yield False


yappi = None

from pydatatask.utils import (
    AReadStreamBase,
    AWriteStreamBase,
    async_copyfile,
    safe_load,
)

from . import repository as repomodule
from .pipeline import Pipeline

l = logging.getLogger(__name__)

# Global semaphores to limit concurrent subprocess operations
_PD_INJECT_SEMAPHORE = None
_PD_CAT_SEMAPHORE = None
_PD_INJECT_LIMIT = None
_PD_CAT_LIMIT = None
_PD_INJECT_ACQUIRED = 0
_PD_CAT_ACQUIRED = 0

def _get_or_create_semaphores():
    """Get or create the global semaphores for subprocess limiting."""
    global _PD_INJECT_SEMAPHORE, _PD_CAT_SEMAPHORE, _PD_INJECT_LIMIT, _PD_CAT_LIMIT
    
    if _PD_INJECT_SEMAPHORE is None:
        # Limit concurrent pd inject operations (default: 32)
        inject_limit = int(os.environ.get("PD_INJECT_CONCURRENCY_LIMIT", "32"))
        _PD_INJECT_LIMIT = inject_limit
        _PD_INJECT_SEMAPHORE = asyncio.Semaphore(inject_limit)
        l.info(f"Created pd inject semaphore with limit: {inject_limit}")
    
    if _PD_CAT_SEMAPHORE is None:
        # Limit concurrent pd cat operations (default: 32)
        cat_limit = int(os.environ.get("PD_CAT_CONCURRENCY_LIMIT", "32"))
        _PD_CAT_LIMIT = cat_limit
        _PD_CAT_SEMAPHORE = asyncio.Semaphore(cat_limit)
        l.info(f"Created pd cat semaphore with limit: {cat_limit}")
    
    return _PD_INJECT_SEMAPHORE, _PD_CAT_SEMAPHORE

async def _acquire_inject_semaphore():
    """Acquire inject semaphore with monitoring."""
    global _PD_INJECT_ACQUIRED
    inject_semaphore, _ = _get_or_create_semaphores()
    
    # Log before acquiring
    available_before = inject_semaphore._value
    l.info(f"🪢 Acquiring pd inject slot (available: {available_before}/{_PD_INJECT_LIMIT}, acquired_count: {_PD_INJECT_ACQUIRED})")
    
    await inject_semaphore.acquire()
    _PD_INJECT_ACQUIRED += 1
    
    available_after = inject_semaphore._value
    l.info(f"✅ Acquired pd inject slot (available: {available_after}/{_PD_INJECT_LIMIT}, acquired_count: {_PD_INJECT_ACQUIRED})")
    
    return inject_semaphore

def _release_inject_semaphore(semaphore):
    """Release inject semaphore with monitoring."""
    global _PD_INJECT_ACQUIRED
    _PD_INJECT_ACQUIRED -= 1
    available_before = semaphore._value
    semaphore.release()
    available_after = semaphore._value
    l.info(f"🔓 Released pd inject slot (available: {available_after}/{_PD_INJECT_LIMIT}, acquired_count: {_PD_INJECT_ACQUIRED})")

async def _acquire_cat_semaphore():
    """Acquire cat semaphore with monitoring."""
    global _PD_CAT_ACQUIRED
    _, cat_semaphore = _get_or_create_semaphores()
    
    # Log before acquiring
    available_before = cat_semaphore._value
    l.info(f"🪢 Acquiring pd cat slot (available: {available_before}/{_PD_CAT_LIMIT}, acquired_count: {_PD_CAT_ACQUIRED})")
    
    await cat_semaphore.acquire()
    _PD_CAT_ACQUIRED += 1
    
    available_after = cat_semaphore._value
    l.info(f"✅ Acquired pd cat slot (available: {available_after}/{_PD_CAT_LIMIT}, acquired_count: {_PD_CAT_ACQUIRED})")
    
    return cat_semaphore

def _release_cat_semaphore(semaphore):
    """Release cat semaphore with monitoring."""
    global _PD_CAT_ACQUIRED
    _PD_CAT_ACQUIRED -= 1
    available_before = semaphore._value
    semaphore.release()
    available_after = semaphore._value
    l.info(f"🔓 Released pd cat slot (available: {available_after}/{_PD_CAT_LIMIT}, acquired_count: {_PD_CAT_ACQUIRED})")


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


def get_command_name():
    args = [
        x.replace('/', '-')
        for x in sys.argv
        if x and not ('-' in x) and not ('=' in x)
    ]
    return "-".join(args)

def write_final_profiling_data():
    """Write final comprehensive profiling data"""
    if yappi is None:
        return

    os.makedirs("/pdt/profiling_data", exist_ok=True)

    command_name = get_command_name()
    pid = os.getpid()

    # Get and save function stats
    func_stats = yappi.get_func_stats()
    func_stats.save(f"/pdt/profiling_data/{command_name}_{pid}_final_profile_funcs.pstat", type="pstat")

    # Save in callgrind format for visualization tools
    func_stats.save(f"/pdt/profiling_data/{command_name}_{pid}_final_profile_funcs.callgrind", type="callgrind")

    # Get and save thread stats
    thread_stats = yappi.get_thread_stats()
    with open(f"/pdt/profiling_data/{command_name}_{pid}_final_profile_threads.txt", "w") as f:
        thread_stats.print_all(out=f)

def write_profiling_snapshot(iteration):
    """Write current profiling snapshot to a file without stopping profiler"""
    if yappi is None:
        return

    # Get current stats
    stats = yappi.get_func_stats()

    os.makedirs("/pdt/profiling_data", exist_ok=True)

    command_name = get_command_name()
    pid = os.getpid()

    # Write to file in pstat format (for later processing)
    stats.save(f"/pdt/profiling_data/{command_name}_{pid}_profile_snapshot_{iteration}.pstat", type="pstat")

    # Optionally clear stats to avoid memory buildup
    # Only do this if you don't need cumulative stats

def build_agent_app(
    pipeline: Pipeline, owns_pipeline: bool = False, flush_period: Optional[timedelta] = None, state_dir: Optional[str] = None, nginx_url: Optional[str] = None
) -> web.Application:
    """Given a pipeline, generate an aiohttp web app to serve its repositories."""

    error_log: Dict[str, Tuple[float, str]] = {}

    if state_dir:
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)

    @web.middleware
    async def authorize_middleware(request: web.Request, handler):
        #env_secret = os.environ.get("AGENT_SECRET", None)
        #allowed = False
        #if request.path == "/health" or request.path == "/nodes":
        #    allowed = True
        #elif request.cookies.get("secret", None) == pipeline.agent_secret:
        #    allowed = True
        #elif env_secret and request.headers.get("Authorization", None) == #f"Bearer {env_secret}":
        #    allowed = True
        #elif env_secret and request.cookies.get("secret", None) == env_secret:
        #    allowed = True
        #if not allowed:
        #    raise web.HTTPForbidden()
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

    async def keys(request: web.Request) -> web.StreamResponse:
        try:
            task = pipeline.tasks[request.match_info["task"]]
            link = task.links[request.match_info["link"]]
            repo = link.repo
            return web.json_response(await repo.keys())
        except KeyError as e:
            raise web.HTTPNotFound() from e

    @parse
    async def get(request: web.Request, repo: repomodule.Repository, job: str) -> web.StreamResponse:
        meta = request.query.getone("meta", None) == "1"
        subpath = request.query.getone("subpath", None)
        do_delete = request.query.getone("delete", None) == "1"
        if not meta and not subpath and not do_delete:
            provider_cache_url = await check_for_alternative_download(repo, job, state_dir)
            if provider_cache_url:
                l.warning(f"Found provider cache url: {provider_cache_url}")
                # Return a redirect to the provider cache url
                raise web.HTTPFound(provider_cache_url)
        response = _DeferredResponse(request)
        if isinstance(repo, repomodule.FilesystemRepository):
            if do_delete:
                await delete_fs(repo, job, response)
            elif meta:
                await cat_fs_meta(repo, job, response, subpath or None)
            elif subpath:
                await cat_fs_entry(repo, job, response, subpath)
            else:
                await cat_data(repo, job, response)
        else:
            await cat_data(repo, job, response, pipeline=pipeline)
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
        from_nginx = request.query.getone("nginx", None)

        inject_target = f"{task.name}.{link_str}"

        up_start_time = time.time()

        # ------------------------------------------------------------
        # Fast-path: data already staged on disk via nginx PUT upload
        # ------------------------------------------------------------
        if from_nginx is not None:
            # "from_nginx" query parameter gives the relative file path inside
            # the upload directory.  We assume nginx stored the file at
            #   /tmp/pdt-uploads/<from_nginx>
            # We inject it into the pipeline via the `pd` CLI instead of
            # reading the body (because nginx has already written it).

            # Resolve absolute file path and make sure it exists
            rel_path = from_nginx.lstrip("/") if from_nginx else job
            abs_path = os.path.join("/tmp/pdt-uploads", rel_path)

            if not os.path.exists(abs_path):
                l.error(f"Expected upload file not found: {abs_path}")
                raise web.HTTPInternalServerError(text="Upload file missing")

            # Build and run the `pd inject` command (async) with concurrency limiting
            cmd = f"pd inject {inject_target} {job} < {abs_path}"
            
            inject_semaphore = await _acquire_inject_semaphore()
            try:
                l.info(f"Running pd inject: {cmd}")
                inj_start_time = time.time()
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await proc.communicate()
                end_time = time.time()
                duration = end_time - inj_start_time

                if proc.returncode != 0:
                    l.error(
                        "pd inject failed (rc=%s) duration=%.2fs stdout=%s stderr=%s",
                        proc.returncode,
                        duration,
                        stdout.decode(errors="replace"),
                        stderr.decode(errors="replace"),
                    )
                    raise web.HTTPInternalServerError(text="Injection failed")

                l.info("pd inject succeeded for %s in %.2f seconds", job, duration)
                await post_process_upload(repo, job, state_dir, nginx_url=nginx_url, inject_target=inject_target)
                end_time = time.time()
                duration = end_time - up_start_time
                l.info(f"🗃️ Upload for {inject_target} {job} completed in {duration:.2f} seconds")
                try:
                    os.unlink(abs_path)
                except Exception as e:
                    l.error(f"Error deleting upload file: {e}")
                return web.Response(text=job)
            finally:
                _release_inject_semaphore(inject_semaphore)

        # ------------------------------------------------------------
        # Traditional path: data streamed in the request body
        # ------------------------------------------------------------
        content = await task.instrument_dump(request.content, link_str, None, job, hostjob)
        await inject_data(repo, job, content, True)
        await post_process_upload(repo, job, state_dir, nginx_url=nginx_url, inject_target=inject_target)
        end_time = time.time()
        duration = end_time - up_start_time
        l.info(f"🗃️ Upload for {inject_target} {job} completed in {duration:.2f} seconds")
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

    async def generate_node_list(pipeline: Pipeline):
        start_time = time.time()
        nodes = []
        for task in pipeline.tasks.values():
            manager = task.manager
            from pydatatask.executor.container_manager import KubeContainerManager
            if isinstance(manager, KubeContainerManager):
                raw_nodes = await manager.cluster.get_nodes()
                for node in raw_nodes:
                    node_name = node.metadata.name
                    node_ip = node.status.addresses[0].address
                    nodes.append({
                        'ip': node_ip,
                        'node_ip': node_ip,
                        'name': node_name
                    })
                raw_pods = await manager.cluster.list_pods_by_label(f"name=host-config")
                for pod in raw_pods:
                    pod_name = pod.metadata.name
                    pod_ip = pod.status.pod_ip
                    pod_node = pod.spec.node_name

                    for node in nodes:
                        if node['name'] == pod_node:
                            node['ip'] = pod_ip
                break
        
        end_time = time.time()
        l.info(f"Loaded {len(nodes)} nodes in {end_time - start_time} seconds")
        return nodes

    async def node_list(request: web.Request) -> web.StreamResponse:
        update_timeout = 4*60*60
        all_nodes = None
        try:
            if state_dir:
                node_state_path = Path(state_dir) / 'nodes.json'
                if node_state_path.exists():
                    node_state = json.load(node_state_path.open())
                    if node_state['updated_at'] > time.time() - update_timeout:
                        all_nodes = node_state['nodes']
                        l.info(f"Using cached node list from {node_state_path}")
                    else:
                        l.warning(f"Node list from {node_state_path} is stale, regenerating by hand, rip performance")
        except Exception as e:
            import traceback
            traceback.print_exc()
            l.error(f"Error loading node list from {node_state_path}: {e}")

        if not all_nodes:
            all_nodes = await generate_node_list(pipeline)

        nodes = []

        from_node = request.query.getone("node_ip", None)

        self_task = None
        for node in all_nodes:
            is_self = node['node_ip'] == from_node
            node_name = node['name']
            if not is_self:
                if 'serv' in node_name:
                    continue
                if 'crit' in node_name:
                    continue
                if 'gpu' in node_name:
                    continue

            if is_self:
                if 'task' in node_name:
                    try:
                        self_task = node_name.split('-')[1]
                    except Exception as e:
                        l.error(f"Error parsing node name: {e}")

            nodes.append({
                **node,
                'self': is_self
            })

        try:
            if self_task:
                nodes = [
                    node
                    for node in nodes
                    if (
                        not 'task' in node['name'] or
                        self_task in node['name']
                    )
                ]
        except Exception as e:
            l.error(f"Error filtering nodes for self task pool: {e}")

        try:
            nodes_brief=', '.join(f"{node['name']}" for node in nodes)
            print(f"Nodes: [ {nodes_brief} ]")
        except Exception as e:
            l.error(f"Error logging nodes: {e}")
        return web.json_response(nodes)

    async def why_ready(request: web.Request) -> web.StreamResponse:
        result = {}
    #     nodes = []
    #     # TODO cache this result
        project_id_to_filter_for = request.query.getone("project_id", None)
        tasks = request.query.getall("task", None)
        if not tasks:
            tasks = list(pipeline.tasks.keys())
        tasks_found = [task for task in tasks if task in pipeline.tasks]
        tasks_not_found = set(tasks) - set(tasks_found)
        if tasks_not_found:
            error_log[request.path] = (time.time(), f"Tasks not found: {', '.join(tasks_not_found)}")
            raise web.HTTPNotFound(text=f"Tasks not found: {', '.join(tasks_not_found)}")


        async def get_stats_of_jobs(task_name):
            import pydatatask
            task: 'pydatatask.Task' = pipeline.tasks[task_name]
            live_tasks = await task.links['live'].repo.keys()
            ready = task.ready
            assert isinstance(ready, repomodule.BlockingRepository)
            ready_source = ready.source
            assert isinstance(ready_source, repomodule.AggregateAndRepository)
            ready_unless = ready.unless
            assert isinstance(ready_unless, repomodule.AggregateOrRepository)
            job_ids = await ready_source.keys()
            if project_id_to_filter_for:
                async def keep_job(job):
                    # import ipdb; ipdb.set_trace()
                    assert 'project_id' in task.input
                    repo = task.input['project_id']
                    if isinstance(repo, repomodule.RelatedItemRepository):
                        return await repo._lookup(job) == project_id_to_filter_for
                    else:
                        return job == project_id_to_filter_for

                job_ids = [job_id for job_id, keep in zip(job_ids, await asyncio.gather(*[keep_job(job) for job in job_ids])) if keep]

            async def get_job_status(job):
                result = {}
                ready = task.ready
                assert isinstance(ready, repomodule.BlockingRepository)
                source = ready.source
                assert isinstance(source, repomodule.AggregateAndRepository)
                unless = ready.unless
                assert isinstance(unless, repomodule.AggregateOrRepository)

                result['ready'] = True # otherwise we wouldn't be here
                result['live'] = job in live_tasks
                result['require_success'] = task.require_success
                result['fail_fast'] = task.fail_fast
                result['failure_ok'] = task.failure_ok
                result['long_running'] = task.long_running
                if 'project_id' not in task.input:
                    result['project_id'] = None
                else:
                    if isinstance(task.input['project_id'], repomodule.RelatedItemRepository):
                        result['project_id'] = await task.input['project_id']._lookup(job)
                    else:
                        # it's just the primary id
                        result['project_id'] = job
                result['job_id'] = job
                result['task_name'] = task_name
                result['done'] = await task.done.info(job)
                if result['done']:
                    result['success'] = result['done']['success']
                    result['timeout'] = result['done']['timeout']
                    result['failure'] = not result['done']['success']
                result['cancelled'] = await task.cancel.contains(job)

                return job, result

            return task_name, dict(await asyncio.gather(*[get_job_status(job) for job in job_ids]))

        tasks_and_jobs = dict(await asyncio.gather(*[get_stats_of_jobs(task_name) for task_name in tasks_found]))
        result = {
            task_name: jobs_stats
            for task_name, jobs_stats in tasks_and_jobs.items()
        }
        return web.json_response(result, dumps=lambda x: orjson.dumps(x).decode())


    async def health(request: web.Request) -> web.StreamResponse:
        return web.Response(text="OK")

    async def status(request: web.Request) -> web.StreamResponse:
        try:
            with open('/shared/status.json', 'r') as f:
                status_data = json.load(f)
            return web.json_response(status_data)
        except FileNotFoundError:
            # Return default status when file is not found
            default_status = {
                "canceled": 0,
                "errored": 0,
                "failed": 0,
                "pending": 0,
                "processing": 0,
                "succeeded": 0,
                "waiting": 0
            }
            return web.json_response(default_status)
        except json.JSONDecodeError as e:
            raise web.HTTPInternalServerError(text=f"Invalid JSON in status file: {e}")
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"Error reading status file: {e}")

    async def semaphore_status(request: web.Request) -> web.StreamResponse:
        """Debug endpoint to check semaphore status."""
        inject_semaphore, cat_semaphore = _get_or_create_semaphores()
        
        status = {
            "pd_inject": {
                "limit": _PD_INJECT_LIMIT,
                "available": inject_semaphore._value,
                "in_use": _PD_INJECT_LIMIT - inject_semaphore._value,
                "acquired_count": _PD_INJECT_ACQUIRED
            },
            "pd_cat": {
                "limit": _PD_CAT_LIMIT,
                "available": cat_semaphore._value,
                "in_use": _PD_CAT_LIMIT - cat_semaphore._value,
                "acquired_count": _PD_CAT_ACQUIRED
            }
        }
        
        # Check for potential leaks
        inject_leak = _PD_INJECT_ACQUIRED != (_PD_INJECT_LIMIT - inject_semaphore._value)
        cat_leak = _PD_CAT_ACQUIRED != (_PD_CAT_LIMIT - cat_semaphore._value)
        
        if inject_leak or cat_leak:
            status["warnings"] = []
            if inject_leak:
                status["warnings"].append(f"Potential pd_inject leak: acquired_count={_PD_INJECT_ACQUIRED} != in_use={_PD_INJECT_LIMIT - inject_semaphore._value}")
            if cat_leak:
                status["warnings"].append(f"Potential pd_cat leak: acquired_count={_PD_CAT_ACQUIRED} != in_use={_PD_CAT_LIMIT - cat_semaphore._value}")
        
        return web.json_response(status)

    app.add_routes([web.get("/keys/{task}/{link}", keys)])
    app.add_routes([web.get("/data/{task}/{link}/{job}", get), web.post("/data/{task}/{link}/{job}", post)])
    app.add_routes([web.get("/stream/{task}/{link}/{job}", stream)])
    app.add_routes([web.post("/query/{task}/{query}", query)])
    app.add_routes([web.post("/cokeydata/{task}/{link}/{cokey}/{job}", cokey_post)])
    app.add_routes([web.get("/errors/{path:.*}", errors)])
    app.add_routes([web.get("/health", health)])
    app.add_routes([web.get("/status/", status)])
    app.add_routes([web.get("/nodes", node_list)])
    app.add_routes([web.get("/why_ready", why_ready)])
    app.add_routes([web.get("/semaphore_status", semaphore_status)])

    async def on_startup(_app: web.Application):
        await pipeline.open()
        # Start yappi profiler if available
        if yappi is not None:
            yappi.set_clock_type("wall")
            yappi.start()

    async def on_shutdown(_app):
        await pipeline.close()
        # Stop yappi profiler and write final data if available
        if yappi is not None:
            yappi.stop()
            write_final_profiling_data()

    if owns_pipeline:
        app.on_startup.append(on_startup)
        app.on_shutdown.append(on_shutdown)
    if flush_period is not None:
        cache_flush = web.AppKey("cache_flush", Task[None])

        async def background_flush():
            while True:
                print("Flushing agent cache...")
                pipeline.cache_flush()
                await sleep(flush_period.total_seconds())

        async def on_startup_flush(app):
            app[cache_flush] = create_task(background_flush())

        app.on_startup.append(on_startup_flush)

    # Add profiling snapshot timer
    if yappi is not None:
        profiling_snapshot = web.AppKey("profiling_snapshot", Task[None])

        async def background_profiling_snapshot():
            iteration = 0
            while True:
                write_profiling_snapshot(iteration)
                iteration += 1
                # Save snapshot every 5 minutes
                await sleep(300)

        async def on_startup_profiling(app):
            app[profiling_snapshot] = create_task(background_profiling_snapshot())

        app.on_startup.append(on_startup_profiling)

    return app

from pathlib import Path

def update_provider_url(key: str, state_dir: str, **kwargs):
    with optional_filelock(state_dir / 'provider_urls.lock'):
        state_dir = Path(state_dir)
        state_file = state_dir / 'provider_urls.yaml'
        if not state_file.exists():
            return None
        
        try:
            current_data = yaml.safe_load(state_file.read_text())
            if current_data is None:
                raise Exception(f"Provider URL file {state_file} is empty")
        except Exception as e:
            import traceback
            traceback.print_exc()
            return None

        current_data.get(key,{}).update(kwargs)

        state_file_tmp = Path(str(state_file) + '.tmp')
        state_file_tmp.write_text(yaml.safe_dump(current_data))
        state_file_tmp.rename(state_file)

def add_provider_url(key: str, url: str, state_dir: str, **kwargs):
    with optional_filelock(state_dir / 'provider_urls.lock'):
        state_dir = Path(state_dir)
        state_file = state_dir / 'provider_urls.yaml'
        state_file_tmp = Path(str(state_file) + '.tmp')
        # TODO error handling

        # Initialize with empty dict if file doesn't exist
        if state_file.exists():
            current_data = yaml.safe_load(state_file.read_text())
            if current_data is None:
                current_data = {}
        else:
            current_data = {}
        
        current_data[key] = dict(
            url=url,
            added_time = int(time.time()),
            **kwargs
        )

        state_file_tmp.write_text(yaml.safe_dump(current_data))

        # Atomic update
        state_file_tmp.rename(state_file)

        return True

def get_provider_url(key: str, state_dir: str):
    if state_dir is None:
        return None
    state_dir = Path(state_dir)
    state_file = state_dir / 'provider_urls.yaml'
    if not state_file.exists():
        return None

    # TODO check to see if file was actually updated?
    try:
        current_data = yaml.safe_load(state_file.read_text())
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None
    return current_data.get(key)



async def store_file_in_azure_storage(file_path: str, container_path: str, timeout=None) -> Optional[str]:
    """Store a file in Azure Storage using async subprocess."""
    file_path = Path(file_path)
    try:
        # Validate file exists
        if not file_path.exists():
            l.error(f"❌ File not found: {file_path}")
            return None

        # Check required environment variables
        required_env_vars = {
            "AZURE_STORAGE_CONTAINER_NAME": "container name",
            "AZURE_STORAGE_ACCOUNT_NAME": "account name",
            "AZURE_STORAGE_STS_TOKEN": "SAS token",
            "AZURE_STORAGE_CONNECTION_STRING": "connection string"
        }
        
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            l.warning(f"⚠️ Missing required Azure storage environment variables: {', '.join(missing_vars)}")
            return None

        storage_container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME")
        deployment_name = os.getenv("DEPLOYMENT_NAME", 'artiphishell')
        container_path = f'backups/{deployment_name}/{container_path}'

        cmd = [
            'az', 'storage', 'blob', 'upload',
            '--container-name', storage_container_name,
            '--account-name', os.getenv("AZURE_STORAGE_ACCOUNT_NAME"),
            '--file', str(file_path),
            '--name', container_path,
            '--sas-token', os.getenv("AZURE_STORAGE_STS_TOKEN"),
            '--connection-string', os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
            '--overwrite',
        ]

        l.info(f"☁️🗃️ Storing {file_path} in {storage_container_name}:{container_path}")
        
        # Create async subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True
        )
        
        # Wait for completion with optional timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            l.error(f"⏰ Azure storage upload timed out after {timeout} seconds")
            process.kill()
            await process.wait()
            return None
        
        # Check return code
        if process.returncode == 0:
            l.info(f"✅ Successfully stored {file_path} in Azure storage")
            
            # Generate read-only SAS URL using connection string only
            try:
                from datetime import datetime, timedelta
                # Generate expiry date (6 days from now) with full UTC time component.
                # Azure CLI expects an ISO-8601 timestamp (yyyy-mm-ddTHH:MM:SSZ) in UTC.
                expiry_dt = datetime.utcnow() + timedelta(days=6)
                expiry_date = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                
                sas_cmd = [
                    'az', 'storage', 'blob', 'generate-sas',
                    '--container-name', storage_container_name,
                    '--name', container_path,
                    '--connection-string', os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
                    '--permissions', 'r',
                    '--expiry', expiry_date,
                    '--https-only',
                    '--full-uri'
                ]
                
                l.info(f"🔗 Generating read-only SAS URL for {container_path}")
                sas_process = await asyncio.create_subprocess_exec(
                    *sas_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                sas_stdout, sas_stderr = await asyncio.wait_for(
                    sas_process.communicate(),
                    timeout=30  # 30 second timeout for SAS generation
                )
                
                if sas_process.returncode == 0:
                    sas_url_raw = sas_stdout.decode('utf-8').strip()
                    # Azure CLI returns the URL as a JSON-encoded string, so we need to decode it
                    try:
                        import json
                        sas_url = json.loads(sas_url_raw)
                    except json.JSONDecodeError:
                        # Fallback: use the raw string if it's not JSON-encoded
                        sas_url = sas_url_raw
                    l.info(f"✅ Generated read-only SAS URL for {container_path}")
                    return sas_url
                else:
                    l.warning(f"⚠️ Failed to generate SAS URL, but upload succeeded")
                    if sas_stderr:
                        l.warning(f"SAS error: {sas_stderr.decode('utf-8', errors='replace')}")
                    return True  # Upload succeeded even if SAS failed
                    
            except asyncio.TimeoutError:
                l.warning(f"⏰ SAS URL generation timed out, but upload succeeded")
                return True
            except Exception as e:
                l.warning(f"⚠️ Error generating SAS URL: {e}, but upload succeeded")
                return True
        else:
            l.error(f"❌ Azure storage upload failed with return code {process.returncode}")
            if stderr:
                l.error(f"Error output: {stderr.decode('utf-8', errors='replace')}")
            if stdout:
                l.debug(f"Standard output: {stdout.decode('utf-8', errors='replace')}")
            return None
            
    except Exception as e:
        l.error(f"Error storing {file_path} in Azure storage: {e}")
        l.error(traceback.format_exc())
        return None


async def post_process_upload(
        item: repomodule.Repository,
        job: str,
        state_dir: str,
        nginx_url: Optional[str] = None,
        inject_target: Optional[str] = None,
    ):
    tmp_file_path = None
    is_moveable_file = False
    try:
        if state_dir is None:
            l.warning(f"Cannot add provider URL for {item}: state_dir is None")
            return None

        if not item.annotations:
            return None

        # Turns out pdt does some sanitization we don't want to skip (symlinks)
        file_path = None

        blob_storage_key = item.annotations.get('blob_storage_key')
        if not blob_storage_key:
            return None

        key = f'{blob_storage_key}/{job}'
        key_file = f'{blob_storage_key}.{job}'
        
        use_azure_storage = item.annotations.get('use_azure_storage')
        use_nginx_cache = item.annotations.get('use_nginx_cache')

        if not use_azure_storage and not use_nginx_cache:
            return None

        if file_path is None:
            import tempfile

            # Create a temporary file to store the data
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file_path = tmp_file.name
                file_path = tmp_file_path

            # Use pd cat subprocess instead of cat_data for better performance
            if inject_target is None:
                l.error(f"Cannot use pd cat for {item}: inject_target is None, falling back to cat_data")
                import aiofiles
                async with aiofiles.open(tmp_file_path, 'wb') as tmp_stream:
                    await cat_data(item, job, tmp_stream)
            else:
                # Use pd cat subprocess with concurrency limiting
                cat_semaphore = await _acquire_cat_semaphore()
                try:
                    l.info(f"🚀 Starting pd cat copy for {inject_target} {job} to {tmp_file_path}")
                    start_time = time.time()
                    
                    # Use shell redirection to write to the temp file
                    cmd = f"pd cat {inject_target} {job} > {tmp_file_path}"
                    
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    
                    stdout, stderr = await proc.communicate()
                    end_time = time.time()
                    duration = end_time - start_time

                    if proc.returncode != 0:
                        l.error(
                            "pd cat failed (rc=%s) duration=%.2fs stdout=%s stderr=%s",
                            proc.returncode,
                            duration,
                            stdout.decode(errors="replace"),
                            stderr.decode(errors="replace"),
                        )
                        # Fall back to cat_data if pd cat fails
                        l.info(f"Falling back to cat_data for {inject_target} {job}")
                        import aiofiles
                        async with aiofiles.open(tmp_file_path, 'wb') as tmp_stream:
                            await cat_data(item, job, tmp_stream)
                    else:
                        l.info(f"✅ pd cat completed for {inject_target} {job} in {duration:.2f} seconds, wrote to {tmp_file_path}")
                    is_moveable_file = True
                finally:
                    _release_cat_semaphore(cat_semaphore)

        if not file_path:
            return None

        if use_azure_storage:
            # Upload to azure storage container and add to provider metadata
            url = await store_file_in_azure_storage(file_path, f"repo_data/{key}")
            if url:
                add_provider_url(key, url, state_dir, provider="azure", last_validated=0)

        elif use_nginx_cache:
            if nginx_url is None:
                l.warning(f"Cannot add nginx cache entry for {item}: nginx_url is None")
                return None

            nginx_cache_dir = state_dir / 'nginx_cache'
            nginx_cache_dir.mkdir(parents=True, exist_ok=True)
            # Make sure it is world readable
            os.chmod(str(nginx_cache_dir), 0o777)
            
            cache_file = (nginx_cache_dir / key_file).resolve()

            if is_moveable_file:
                # Move the file to the nginx cache directory
                shutil.move(file_path, cache_file)
            else:
                # Copy the file to the nginx cache directory
                shutil.copy(file_path, cache_file)
            os.chmod(str(cache_file), 0o777)

            url = f"{nginx_url}/cache/{key_file}"

            # Add to provider metadata
            add_provider_url(
                key, url,
                state_dir, provider="nginx", last_validated=0,
                cache_file=str(cache_file),
                last_used=int(time.time()),
                hit_count=0
            )
            l.info(f"🌐 Added nginx cache entry for {key} at {cache_file} via {url}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Clean up the temporary file
        try:
            if tmp_file_path is not None:
                os.unlink(tmp_file_path)
        except FileNotFoundError:
            pass



async def check_for_alternative_download(item: repomodule.Repository, job: str, state_dir: str):
    if not item.annotations:
        return None
    blob_storage_key = item.annotations.get('blob_storage_key')
    if not blob_storage_key:
        return None

    key = f'{blob_storage_key}/{job}'

    entry = get_provider_url(key, state_dir)
    if not entry:
        return None

    try:
        if entry.get('invalid'):
            return None
        if entry.get('provider') == 'azure':
            azure_check_cooldown = 300

            url = entry.get('url')
            if not url:
                return None

            if not entry.get('last_validated') or time.time() - entry.get('last_validated') > azure_check_cooldown:
                if is_azure_url_valid(url, timeout=10):
                    try:
                        update_provider_url(key, state_dir, last_validated=int(time.time()))
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                else:
                    try:
                        update_provider_url(key, state_dir, invalid=True)
                        l.warning(f"🌐 Azure URL for {key} is no longer valid")
                    except Exception as e:
                        import traceback
                        traceback.print_exc()

                    return None
            return url
        if entry.get('provider') == 'nginx':
            # First we check to see if the file still exists on disk
            cache_file = entry.get('cache_file')
            if not cache_file or not os.path.exists(cache_file):
                # The file is no longer in the cache, so we need to invalidate the entry
                l.warning(f"🌐 Nginx cache entry for {key} at {cache_file} is no longer valid")
                try:
                    update_provider_url(key, state_dir, invalid=True)
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                return None

            url = entry.get('url')
            if not url:
                return None
            
            # Otherwise validate that we can access the file from azure 
            if not is_nginx_url_valid(url, timeout=5):
                l.warning(f"🌐 Nginx cache entry for {key} at {url} is no longer valid")
                try:
                    update_provider_url(key, state_dir, invalid=True)
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                return None

            do_update_hitcount = False
            # We want to only update with useful info, to avoid thrashing the yaml file
            if entry.get('hit_count', 0) < 2:
                do_update_hitcount = True
            elif entry.get('last_used', 0) < time.time() - 600:
                do_update_hitcount = True

            if do_update_hitcount:
                # Update the hit_count and the last_recent download
                update_provider_url(key, state_dir, hit_count=entry.get('hit_count',0) + 1, last_used=int(time.time()))

            return url
    except Exception as e:
        import traceback
        traceback.print_exc()

    return None


async def cat_data(item: repomodule.Repository, job: str, stream: AWriteStreamBase, pipeline: Optional[Pipeline] = None):
    """Copy one job of a repository to a stream."""
    if isinstance(item, repomodule.BlobRepository):
        try:
            async with await item.open(job, "rb") as fp:
                await async_copyfile(fp, stream)
        except FileNotFoundError as e:
            raise web.HTTPNotFound() from e
    elif isinstance(item, repomodule.MetadataRepository):
        data_bytes = await item.info(job)
        data_str = yaml.safe_dump(data_bytes, None)
        if isinstance(data_str, str):
            await stream.write(data_str.encode())
        else:
            await stream.write(data_str)
    elif isinstance(item, repomodule.FilesystemRepository):
        try:
            await item.get_tarball(job, stream)
        except FileNotFoundError as e:
            raise web.HTTPNotFound() from e
    elif isinstance(item, repomodule.LiveContainerRepository):
        # For live repos, we want to disable the pod cache
        if pipeline:
            # Get a handle to the pod manager
            for task in pipeline.tasks.values():
                manager = task.manager
                from pydatatask.executor.container_manager import KubeContainerManager
                if isinstance(manager, KubeContainerManager):
                    # 5 second ttl on the live cache to reduce latency
                    # but to prevent a ton of requests from DOSing the cluster
                    manager.cluster.pod_cache_ttl = 5
                    break

        live_containers = [x async for x in item.unfiltered_iter()]
        await stream.write(yaml.safe_dump(True if job in live_containers else False).encode())
    else:
        raise TypeError(f"Unknown repository type: {type(item)=!r}, {item=!r}, {job=!r}")


async def delete_fs(item: repomodule.FilesystemRepository, job: str, stream: AWriteStreamBase):
    if isinstance(item, repomodule.FilesystemRepository):
        l.info(f"🗑️ Deleting {job} from {item}")
        await item.delete(job)
        await stream.write(f"{job} Deleted\n".encode())
    else:
        raise TypeError(f"Unknown repository type: {type(item)=!r}, {item=!r}, {job=!r}")


async def cat_fs_meta(item: repomodule.FilesystemRepository, job: str, stream: AWriteStreamBase, subpath:str=None):
    if subpath:
        # Find the first file with this name:
        async for entry in item.iterdir(job, subpath):
            await stream.write(f"{entry}/\n".encode())
        return

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


# ------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------


def is_nginx_url_valid(url: str, timeout: int = 5) -> bool:
    """Return True if the given Nginx URL still grants access.
    """
    response = requests.head(url, allow_redirects=False, timeout=timeout)
    return response.status_code == 200

def is_azure_url_valid(url: str, timeout: int = 5) -> bool:
    """Return True if the given Azure (SAS) URL still grants access.

    The check is performed with an HTTP HEAD request so that no payload is
    downloaded. The call is synchronous and uses the ``requests`` library.

    Parameters
    ----------
    url : str
        The fully-qualified Azure blob/file URL, including SAS token if
        applicable.
    timeout : int, optional
        Socket timeout (seconds) for the request. Defaults to 5 seconds.

    Notes
    -----
    * ``200`` or ``206`` → considered *valid*.
    * ``403`` (SignatureExpired / AuthenticationFailed) or any 4xx/5xx
      status → *invalid*.
    * Network-level exceptions (DNS failure, timeout, etc.) also return
      *invalid*.
    """

    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout)

        # 200 OK for most blobs, 206 Partial Content if HEAD not allowed but
        # Range request succeeds. Treat both as valid.
        if response.status_code in (200, 206):
            return True

        # Common Azure errors
        if response.status_code == 403:
            # Authentication failed — likely the SAS expired or was revoked.
            return False

        if response.status_code == 404:
            # Blob no longer exists.
            return False

        # Any other 4xx/5xx → assume invalid.
        return False

    except requests.RequestException as e:
        l.debug(f"Azure URL validity check failed: {e}")
        return False
