"""The top-level script you write using pydatatask should call `pydatatask.main.main` in its ``if __name__ ==main
'__main__'`` block. This will parse ``sys.argv`` and display the administration interface for the pipeline.

The help screen should look something like this:

.. code::

    $ python3 main.py --help
      usage: main.py [-h] {update,run,status,trace,rm,ls,cat,inject,launch,shell} ...

    positional arguments:
      {run,status,trace,rm,ls,cat,inject,launch,shell}
        run                 Run update in a loop until everything is quiet
        status              View the pipeline status
        trace               Track a job's progress through the pipeline
        rm                  Delete data from the pipeline
        ls                  List jobs in a repository
        cat                 Print data from a repository
        inject              Dump data into a repository
        launch              Manually start a task
        shell               Launch an interactive shell to interrogate the pipeline

    options:
      -h, --help            show this help message and exit
"""

from __future__ import annotations

import os

import yaml

yappi = None

if yappi is not None:
    yappi.set_clock_type("wall") # Use set_clock_type("wall") for wall time
    yappi.start()

from typing import (
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
import argparse
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys

from aiohttp import web
from networkx.drawing.nx_pydot import write_dot
import aiofiles
import uvloop
from crs_telemetry.utils import get_otel_tracer, init_otel
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.aiohttp_server import AioHttpServerInstrumentor

from . import repository as repomodule
from . import task as taskmodule
from .agent import build_agent_app
from .agent import cat_data as cat_data_inner
from .agent import inject_data as inject_data_inner
from .pipeline import Pipeline
from .utils import AsyncQueueStream, async_copyfile
# from .visualize import run_viz
from .assets.vizualize import run_viz

try:
    from . import fuse
except ModuleNotFoundError:
    fuse = None  # type: ignore[assignment]

init_otel("pydatatask", "infra", "pydatatask")
tracer = get_otel_tracer()
logging.getLogger("opentelemetry.attributes").disabled = True

log = logging.getLogger(__name__)
token_re = re.compile(r"\w+(?:\.\w+)+")

__all__ = (
    "main",
    "cat_data",
    "list_data",
    "delete_data",
    "inject_data",
    "print_status",
    "print_trace",
    "launch",
    "shell",
    "run",
)

FAIL_FAST = os.getenv("PDT_MAIN_FAIL_FAST", "").lower() not in ("", "0", "false", "no")

# pylint: disable=missing-function-docstring,missing-class-docstring


def main(
    pipeline: Pipeline,
    instrument: Optional[Callable[[argparse._SubParsersAction], None]] = None,
    has_local_fs: bool = True,
):
    """The pydatatask main function! Call this with the pipeline you've constructed to parse ``sys.argv`` and
    display the pipeline administration interface.

    If you like, you can pass as the ``instrument`` argument a function which will add additional commands to the menu.
    """
    logging.basicConfig()
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help="Enable more verbose logging")
    parser.add_argument(
        "--fail-fast", action="store_true", help="Do not catch exceptions thrown during routine operations"
    )
    parser.add_argument(
        "--task", "-t", dest="tasks_allowlist", action="append", default=[], help="Only manage these tasks"
    )
    parser.add_argument(
        "--not-task", "-T", dest="tasks_denylist", action="append", default=[], help="Do not manage these tasks"
    )
    parser.add_argument(
        "--enable-task-dependencies", dest="enable_task_dependencies", action="store_true", default=False, help="Enable tasks that are not in the allowlist if they are dependencies of other tasks"
    )
    parser.add_argument(
        "--debug-trace",
        action="store_true",
        help="Make every worker script print out its execution trace for debugging",
    )
    parser.add_argument(
        "--require-success",
        action="store_true",
        default=None,
        help="Raise an error when workers fail instead of marking them as completed-but-failed",
    )
    parser.add_argument(
        "--global-template-env",
        action="append",
        default=[],
        help="Add a value (KEY=VALUE) to the template environment for the entire pipeline",
    )
    parser.add_argument(
        "--global-script-env",
        action="append",
        default=[],
        help="Add a value (KEY=VALUE) to the shell environment for the entire pipeline",
    )

    subparsers = parser.add_subparsers(dest=argparse.SUPPRESS, required=True)

    parser_run = subparsers.add_parser("run", help="Run update in a loop until everything is quiet")
    parser_run.add_argument("--once", action="store_true", help="Run only a single loop of updates")
    parser_run.add_argument("--forever", action="store_true", help="Run forever")
    parser_run.add_argument("--launch-once", action="store_true", help="Only evaluates tasks-to-launch once")
    parser_run.set_defaults(func=run)
    parser_run.set_defaults(timeout=None)

    parser_check_templates = subparsers.add_parser("check-templates", help="Check the templates for templating errors")
    parser_check_templates.add_argument(
        "--backup-dir",
        dest="backup_dir",
        type=Path,
        help="directory in the backup structure with which template errors should be checked",
    )
    parser_check_templates.add_argument("tasks", nargs="*", help="Only look at these tasks")
    parser_check_templates.set_defaults(func=check_templates)

    parser_status = subparsers.add_parser("status", help="View the pipeline status")
    parser_status.add_argument(
        "--all",
        "-a",
        dest="all_repos",
        action="store_true",
        help="Show internal repositories",
    )
    parser_status.add_argument(
        "--as-json",
        "-j",
        dest="as_json",
        action="store_true",
        help="Show status as JSON",
    )
    parser_status.add_argument(
        "--output",
        "-o",
        dest="output",
        type=Path,
        help="Output path for JSON",
    )
    parser_status.add_argument("tasks", nargs="*", help="Only look at these tasks")
    parser_status.set_defaults(func=print_status)

    parser_trace = subparsers.add_parser("trace", help="Track a job's progress through the pipeline")
    parser_trace.add_argument(
        "--all",
        "-a",
        dest="all_repos",
        action="store_true",
        help="Show internal repositories",
    )
    parser_trace.add_argument("job", nargs="+", help="Name of job to trace")
    parser_trace.set_defaults(func=print_trace)

    parser_delete = subparsers.add_parser("rm", help="Delete data from the pipeline")
    parser_delete.add_argument("--recursive", "-r", action="store_true", help="Delete dependant data too")
    parser_delete.add_argument(
        "data",
        type=str,
        help="Name of repository [task.repo] or task from which to delete data",
        metavar="repo",
    )
    parser_delete.add_argument("job", type=str, nargs="+", help="Name of job of which to delete data")
    parser_delete.set_defaults(func=delete_data)

    parser_ls = subparsers.add_parser("ls", help="List jobs in a repository")
    parser_ls.add_argument(
        "data",
        type=str,
        nargs="+",
        help="Name of repository [task.repo] from which to list data",
        metavar="repo",
    )
    parser_ls.set_defaults(func=list_data)

    parser_cat = subparsers.add_parser("cat", help="Print data from a repository")
    parser_cat.add_argument(
        "data", type=str, help="Name of repository [task.repo] from which to print data", metavar="repo"
    )
    parser_cat.add_argument("job", type=str, help="Name of job of which to delete data")
    parser_cat.set_defaults(func=cat_data)

    parser_inject = subparsers.add_parser("inject", help="Dump data into a repository")
    parser_inject.add_argument(
        "data", type=str, help="Name of repository [task.repo] to which to inject data", metavar="repo"
    )
    parser_inject.add_argument("job", type=str, help="Name of job of which to inject data")
    parser_inject.set_defaults(func=inject_data)

    parser_launch = subparsers.add_parser("launch", help="Manually start a task")
    parser_launch.add_argument(dest="task_name", type=str, help="Name of task to launch")
    parser_launch.add_argument("job", type=str, help="Name of job to launch task on")
    parser_launch.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Launch even if start is inhibited by data",
    )
    parser_launch.add_argument("--sync", action="store_true", help="Run the task in-process, if possible")
    parser_launch.add_argument(
        "--meta",
        action="store_true",
        default=False,
        help="Store metadata related to task completion",
    )
    parser_launch.add_argument(
        "--no-meta",
        action="store_false",
        help="Do not store metadata related to task completion",
        dest="meta",
    )
    parser_launch.add_argument(
        "--fail-fast", action="store_true", help="Do not catch exceptions thrown during routine operations"
    )
    parser_launch.add_argument(
        "--require-success",
        action="store_true",
        help="Raise an error when workers fail instead of marking them as completed-but-failed",
    )
    parser_launch.add_argument(
        "--debug-trace",
        action="store_true",
        help="Make every worker script print out its execution trace for debugging",
    )
    parser_launch.set_defaults(func=launch)

    parser_shell = subparsers.add_parser("shell", help="Launch an interactive shell to interrogate the pipeline")
    parser_shell.set_defaults(func=shell)

    parser_why = subparsers.add_parser(
        "why-ready", help="Show the underpinnings of why a given task could be ready or not ready to schedule"
    )
    parser_why.add_argument("task", help="Task to analyze")
    parser_why.set_defaults(func=why_ready)

    if has_local_fs:
        parser_graph = subparsers.add_parser("graph", help="Generate a the pipeline graph visualizations")
        parser_graph.add_argument(
            "--out-dir", "-o", help="The directory to write the graphs to", type=Path, default=None
        )
        parser_graph.set_defaults(func=graph)

        parser_backup = subparsers.add_parser("backup", help="Copy contents of repositories to a given folder")
        parser_backup.add_argument("--all", dest="all_repos", action="store_true", help="Backup all repositories")
        parser_backup.add_argument(
            "--shallow",
            action="store_true",
            help="Back up in a way that disregards being able to restore complex repositories",
        )
        parser_backup.add_argument("backup_dir", help="The directory to backup to")
        parser_backup.add_argument("repos", nargs="*", help="The repositories to back up")
        parser_backup.set_defaults(func=action_backup)

        parser_restore = subparsers.add_parser("restore", help="Copy contents of repositories from a given folder")
        parser_restore.add_argument("--all", dest="all_repos", action="store_true", help="Restore all repositories")
        parser_restore.add_argument("backup_dir", help="The directory to restore from")
        parser_restore.add_argument("repos", nargs="*", help="The repositories to restore")
        parser_restore.set_defaults(func=action_restore)

    parser_http_agent = subparsers.add_parser(
        "agent-http", help="Launch an http server to accept reads and writes from repositories"
    )
    parser_http_agent.set_defaults(func=http_agent)
    parser_http_agent.add_argument("--host", help="The host to listen on", default="0.0.0.0")
    parser_http_agent.add_argument("--override-port", help="The port to listen on", type=int)
    parser_http_agent.add_argument("--flush-seconds", type=int, help="How often to flush the query cache")
    parser_http_agent.add_argument("--state-dir", type=str, help="For provider cache state / node cache, provide a writeable directory")
    parser_http_agent.add_argument("--nginx-url", type=str, help="For provider nginx, provide a base url")

    parser_http_multi = subparsers.add_parser(
        "agent-http-multi", help="Launch multiple http agents balanced behind nginx"
    )
    parser_http_multi.set_defaults(func=http_agent_multi)
    parser_http_multi.add_argument("--host", help="The host to listen on", default="0.0.0.0")
    parser_http_multi.add_argument("--count", help="The number of agents to use", default=4, type=int)

    parser_viz = subparsers.add_parser("viz", help="Show Visualization of Running Pipeline")
    parser_viz.add_argument("--port", type=int, help="The port to serve on", default=8050)
    parser_viz.add_argument("--host", help="The host to bind on", default="0.0.0.0")
    parser_viz.set_defaults(func=run_viz)

    parser_fuse = subparsers.add_parser("fuse", help="Mount a fuse filesystem to explore the pipeline's repos")
    parser_fuse.set_defaults(func=fuse.main if fuse is not None else fuse_stub)
    parser_fuse.add_argument("path", help="The mountpoint")
    parser_fuse.add_argument("--verbose", "-v", dest="debug", action="store_true", help="Show FUSE debug logging")

    if instrument is not None:
        instrument(subparsers)

    args = parser.parse_args()
    ns = vars(args)
    func = ns.pop("func")
    pipeline.settings(
        fail_fast=ns.pop("fail_fast"),
        task_allowlist=ns.pop("tasks_allowlist") or None,
        task_denylist=ns.pop("tasks_denylist") or None,
        debug_trace=ns.pop("debug_trace"),
        require_success=ns.pop("require_success"),
        enable_task_dependencies=ns.pop("enable_task_dependencies", False),
    )
    pipeline.global_template_env.update(dict([line.split("=", 1) for line in ns.pop("global_template_env") or []]))
    pipeline.global_script_env.update(dict([line.split("=", 1) for line in ns.pop("global_script_env") or []]))
    if ns.pop("verbose"):
        logging.getLogger("pydatatask").setLevel("DEBUG")
    result_or_coro = func(pipeline, **ns)

    uvloop.install()

    if asyncio.iscoroutine(result_or_coro):
        if yappi is not None:
            with yappi.run():
                return asyncio.run(main_inner(pipeline, result_or_coro))
        else:
            return asyncio.run(main_inner(pipeline, result_or_coro))
    else:
        return result_or_coro


async def main_inner(pipeline, coro):
    async with pipeline:
        await coro


def shell(pipeline: Pipeline):
    pydatatask = __import__("pydatatask")
    assert pipeline
    assert pydatatask

    ipython = __import__("IPython")
    ipython.embed(using="asyncio")


async def graph(pipeline: Pipeline, out_dir: Optional[Path]):
    if out_dir is None:
        out_dir = Path.cwd() / "latest_graphs"

    os.makedirs(out_dir, exist_ok=True)

    assert os.path.isdir(out_dir)
    with open(out_dir / "task_graph.md", "w", encoding="utf-8") as f:
        f.write("# Task Graph\n\n")
        f.write("```mermaid\n")
        f.write(await pipeline.mermaid_task_graph)
        f.write("\n```\n\n")

    with open(out_dir / "graph.md", "w", encoding="utf-8") as f:
        f.write("# Data Graph\n\n")
        f.write("```mermaid\n")
        f.write(await pipeline.mermaid_graph)
        f.write("\n```\n\n")

    with open(out_dir / "task_graph.dot", "w", encoding="utf-8") as f:
        write_dot(pipeline.task_graph, f)

    with open(out_dir / "graph.dot", "w", encoding="utf-8") as f:
        write_dot(pipeline.graph, f)


@tracer.start_as_current_span("pydatatask.http_agent")
def http_agent(
    pipeline: Pipeline, host: str, override_port: Optional[int] = None, flush_seconds: Optional[float] = None, state_dir: Optional[str] = None, nginx_url: Optional[str] = None
) -> None:
    logging.getLogger("aiohttp.access").setLevel("DEBUG")
    app = build_agent_app(pipeline, True, None if flush_seconds is None else timedelta(seconds=flush_seconds), state_dir=state_dir, nginx_url=nginx_url)
    web.run_app(app, host=host, port=override_port or pipeline.agent_port)


@tracer.start_as_current_span("pydatatask.http_agent_multi")
def http_agent_multi(pipeline: Pipeline, host: str, count: int) -> None:
    nginx = shutil.which("nginx")
    if nginx is None:
        raise Exception("Cannot run agent-multi without nginx on PATH")

    servers = "\n        ".join(f"server localhost:{pipeline.agent_port + 1 + i};" for i in range(count))

    client_body_temp_path = Path("/tmp/pydatatask-nginx_client_body_temp")
    client_body_temp_path.mkdir(exist_ok=True)

    nginx_config = f"""
error_log /dev/stderr info;
pid /dev/null;
daemon off;

events {{
    worker_connections 2048;
}}

http {{
    access_log /dev/stderr combined;
    error_log /dev/stderr info;
    client_max_body_size 15G;
    client_body_temp_path {client_body_temp_path};
    upstream custom-domains {{
        {servers}
    }}
    server {{
        listen       {pipeline.agent_port};
        server_name  _;

        location / {{
            proxy_pass http://custom-domains;
            proxy_http_version   1.1;
            proxy_set_header     Upgrade $http_upgrade;
            proxy_set_header     Connection upgrade;
            proxy_set_header     Host $host;
            proxy_buffering off;
            proxy_request_buffering off;
        }}
    }}
}}
    """

    agents = [
        subprocess.Popen(  # pylint: disable=consider-using-with
            [
                sys.executable,
                "-m",
                "pydatatask.cli.main",
                "agent-http",
                "--host",
                host,
                "--override-port",
                str(pipeline.agent_port + 1 + i),
            ]
        )
        for i in range(count)
    ]
    config_filename = f"/tmp/pydatatask-nginx-{pipeline.agent_port}.conf"
    with open(config_filename, "w", encoding="utf-8") as f:
        f.write(nginx_config)
    process_result = subprocess.run([nginx, "-c", config_filename], check=False, stderr=subprocess.STDOUT)
    for agent in agents:
        agent.terminate()
        agent.wait()

    if process_result.returncode != 0:
        raise Exception("nginx failed to start")


@tracer.start_as_current_span("pydatatask.run")
async def run(
    pipeline: Pipeline,
    forever: bool,
    launch_once: bool,
    timeout: Optional[float],
    once: bool = False,
):
    start = asyncio.get_running_loop().time()
    do_launch = True
    while await pipeline.update(do_launch) or forever:
        if once:
            break
        if launch_once:
            do_launch = False
        await asyncio.sleep(1)
        if timeout and asyncio.get_running_loop().time() - start > timeout:
            raise TimeoutError("Pipeline run timeout")


def get_links(pipeline: Pipeline, all_repos: bool, tasks: Optional[List[str]]) -> Iterable[taskmodule.Link]:
    seen = set()
    for task in pipeline.tasks.values():
        if tasks is not None and task.name not in tasks:
            continue
        for link in task.links.values():
            if not all_repos and not link.is_status and not link.is_input and not link.is_output:
                continue
            if id(link) in seen:
                continue
            seen.add(id(link))
            yield link
def get_tasks_and_links(pipeline: Pipeline, all_repos: bool, tasks: Optional[List[str]]) -> Iterable[Tuple[taskmodule.Task, taskmodule.Link]]:
    seen = set()
    for task in pipeline.tasks.values():
        if tasks is not None and task.name not in tasks:
            continue
        for link in task.links.values():
            if not all_repos and not link.is_status and not link.is_input and not link.is_output:
                continue
            if id(link) in seen:
                continue
            seen.add(id(link))
            yield task, link


async def check_template_templates(template, env):
    try:
        await taskmodule.render_template(template, env)
    except Exception as e:
        raise ValueError(f"Template {template} has an error: {e}") from e

async def build_task_template_env(task: taskmodule.Task, backup_dir: Optional[Path]=None) -> Dict[str, str]:
    """Build the template environment for a task."""
    env = {}
    pre_env = {}
    if backup_dir:
        with open(backup_dir / f"{task.name}.yaml", "r", encoding="utf-8") as f:
            pre_env.update(yaml.safe_load(f))
    for link_name, link in task.links.items():
        if link.kind == taskmodule.LinkKind.InputId:
            env[link_name] = '01233456789abcdef'
        elif link.kind == taskmodule.LinkKind.InputMetadata or link.cokeyed:
            if link_name not in pre_env:
                env[link_name] = {'task': task.name, 'link': link_name}
                assert False, f"Link {link_name} for task {task.name} is not in the pre_env, please add it to the backup directory"
            else:
                env[link_name] = pre_env[link_name]
        elif link.kind in (taskmodule.LinkKind.InputFilepath, taskmodule.LinkKind.OutputFilepath):
            env[link_name] = f'/{str(link.kind)}/'
        elif link.kind in (taskmodule.LinkKind.StreamingInputFilepath, taskmodule.LinkKind.StreamingOutputFilepath) and link.DANGEROUS_filename_is_key:
            env[link_name] = {
                'lock_dir': f'/{str(link.kind)}/lock',
                'main_dir': f'/{str(link.kind)}/main',
            }
        elif link.kind == taskmodule.LinkKind.Cancel:
            env[link_name] = None

        elif link.kind is None:
            env[link_name] = None
        else:
            assert False, f"Unknown link kind {link.kind} for {task.name}.{link_name}"

    return env

async def check_templates(
    pipeline: Pipeline,
    backup_dir: Optional[Path] = None,
    tasks: Optional[List[str]] = None,
):
    tasks = tasks or None
    for task_name, task in pipeline.tasks.items():
        if tasks is not None and task_name not in tasks:
            continue
        log.info("Checking templates for task %s", task_name)
        env = await build_task_template_env(task, backup_dir)
        await check_template_templates(str(task.max_concurrent_jobs), env)

        if isinstance(task, taskmodule.ContainerTask):
            await check_template_templates(task.template, env)
        else:
            assert False, f"Task {task_name} is not a ContainerTask, cannot check templates"


async def print_status(
    pipeline: Pipeline,
    all_repos: bool,
    as_json: bool = False,
    output: Optional[Path] = None,
    tasks: Optional[List[str]] = None,
):
    tasks = tasks or None
    link_list = list(get_links(pipeline, all_repos, tasks))
    repo_set = {link.repo for link in link_list}
    repo_set |= {cokeyed for link in link_list for cokeyed in link.cokeyed.values()}
    repo_list = list(repo_set)
    repo_members: Dict[repomodule.Repository, List[str]] = dict(
        zip(repo_list, await asyncio.gather(*(repo.keys() for repo in repo_list)))
    )

    result: DefaultDict[str, Dict[str, Tuple[List[str], Dict[str, List[str]]]]] = defaultdict(dict)
    for task in pipeline.tasks.values():
        for link_name, link in sorted(
            task.links.items(),
            key=lambda x: 0 if x[1].is_input else 1 if x[1].is_status else 2,
        ):
            if link in link_list:
                result[task.name][link_name] = repo_members[link.repo], {
                    cokey: repo_members[cokeyed] for cokey, cokeyed in link.cokeyed.items()
                }

    def fmt_jobs(jobs: List[str]) -> str:
        if not jobs:
            return ""
        if len(jobs) <= 3:
            return f' ({", ".join(jobs)})'
        return f' ({", ".join(jobs[:3])}, ...)'

    msg = ""
    if not as_json:
        for task_name, links in result.items():
            msg += f"{task_name}\n"
            for link_name, (jobs, cokeys) in links.items():
                msg += f"  {task_name}.{link_name} {len(jobs)}{fmt_jobs(jobs)}\n"
                for cokey_name, cokey_jobs in cokeys.items():
                    msg += f"  {task_name}.{link_name}.{cokey_name}{fmt_jobs(cokey_jobs)}\n"
            msg += "\n"
    else:
        msg = json.dumps(result, indent=2)

    if output is None:
        print(msg)
    else:
        with open(output, "w", encoding="utf-8") as f:
            f.write(msg)


async def print_trace(pipeline: Pipeline, all_repos: bool, job: List[str]):
    async def inner(repo: repomodule.Repository):
        return [j for j in job if await repo.contains(j)]

    link_list = list(get_links(pipeline, all_repos))
    repo_list = list(set(link.repo for link in link_list))
    repo_members = dict(zip(repo_list, await asyncio.gather(*(inner(repo) for repo in repo_list))))

    for task in pipeline.tasks.values():
        print(task.name)
        for link_name, link in sorted(
            task.links.items(),
            key=lambda x: 0 if x[1].is_input else 1 if x[1].is_status else 2,
        ):
            if link in link_list:
                print(f"{task.name}.{link_name} {' '.join(repo_members[link.repo])}")
        print()


def lookup_dotted(
    pipeline: Pipeline, ref: str, enable_footprint: bool = False
) -> Union[repomodule.Repository, taskmodule.Task]:
    if enable_footprint and ".__footprint." in ref:
        real_ref, _, footprint_idx_str = ref.rsplit(".", 2)
        footprint_idx = int(footprint_idx_str)
        repo = lookup_dotted(pipeline, real_ref)
        assert isinstance(repo, repomodule.Repository)
        for i, footprint_repo in enumerate(repo.footprint()):
            if i == footprint_idx:
                return footprint_repo
        raise KeyError("Implicit dependency " + footprint_idx_str)

    item: Union[repomodule.Repository, taskmodule.Task]
    if "." in ref:
        taskname, reponame = ref.split(".", 1)
        if "." in reponame:
            reponame, cokeyname = reponame.split(".", 1)
            item = pipeline.tasks[taskname].links[reponame].cokeyed[cokeyname]
        else:
            item = pipeline.tasks[taskname].links[reponame].repo
    else:
        item = pipeline.tasks[ref]
    return item


async def delete_data(pipeline: Pipeline, data: str, recursive: bool, job: List[str]):
    item = lookup_dotted(pipeline, data)

    for dependant in pipeline.dependants(item, recursive):
        if isinstance(dependant, repomodule.Repository):
            if job[0] == "__all__":
                jobs = [x async for x in dependant]
                check = False
            else:
                jobs = job
                check = True

            async def del_job(j, dep):
                await dep.delete(j)
                print(j, dep)

            await asyncio.gather(*[del_job(j, dependant) for j in jobs if not check or await dependant.contains(j)])


async def list_data(pipeline: Pipeline, data: List[str]):
    input_text = " ".join(data)
    tokens = token_re.findall(input_text)
    namespace = {name.replace("-", "_"): TaskNamespace(task) for name, task in pipeline.tasks.items()}
    for token in tokens:
        if token.count(".") == 1:
            task, repo = token.split(".")
            await namespace[task]._consume(repo)
    for token in tokens:
        if token.count(".") == 2:
            task, repo, cokey = token.split(".")
            await namespace[task]._consume(repo)
            await getattr(namespace[task], repo)._consume(cokey)
    result = eval(input_text, {}, namespace)  # pylint: disable=eval-used

    for job in sorted(result):
        print(job)


class TaskNamespace:
    def __init__(self, task: taskmodule.Task):
        self._task = task
        self._repos: Dict[str, LinkSet] = {}

    def __getattr__(self, item):
        return self._repos[item]

    async def _consume(self, repo: str):
        result: Set[str] = set()
        async for x in self._task.links[repo].repo:
            result.add(x)
        self._repos[repo] = LinkSet(self._task.links[repo], result)


class LinkSet(set):
    def __init__(self, link: taskmodule.Link, members: Set[str]):
        super().__init__(members)
        self._link = link
        self._cokeys: Dict[str, Set[str]] = {}

    def __getattr__(self, item):
        return self._cokeys[item]

    async def _consume(self, cokey: str):
        result: Set[str] = set()
        async for x in self._link.cokeyed[cokey]:
            result.add(x)
        self._cokeys[cokey] = result


async def cat_data(pipeline: Pipeline, data: str, job: str):
    item = lookup_dotted(pipeline, data)
    if isinstance(item, taskmodule.Task):
        print("Cannot `cat` a task")
        return 1

    try:
        await cat_data_inner(item, job, aiofiles.stdout_bytes)
    except TypeError:
        if FAIL_FAST:
            raise
        print("Error: cannot serialize a job in a repository which is not a blob or metadata or filesystem")
        return 1


@tracer.start_as_current_span("pydatatask.inject_data")
async def inject_data(pipeline: Pipeline, data: str, job: str):
    item = lookup_dotted(pipeline, data)
    if isinstance(item, taskmodule.Task):
        print("Cannot `inject` a task")
        return 1

    try:
        await inject_data_inner(item, job, aiofiles.stdin_bytes, False)
    except TypeError:
        if FAIL_FAST:
            raise
        print("Error: cannot deserialize a job in a repository which is not a blob or metadata")
        return 1
    except ValueError as e:
        if FAIL_FAST:
            raise
        print(f"Bad data structure: {e.args[0]}")
        return 1


@tracer.start_as_current_span("pydatatask.launch")
async def launch(
    pipeline: Pipeline,
    task_name: str,
    job: str,
    sync: bool,
    meta: bool,
    force: bool,
):
    task = pipeline.tasks[task_name]
    pipeline.settings(sync, meta)

    if force or await task.ready.contains(job):
        await task.launch(job, 0)
    else:
        log.warning("Task is not ready to launch - use -f to force")
        return 1


@tracer.start_as_current_span("pydatatask.action_backup")
async def action_backup(
    pipeline: Pipeline, backup_dir: str, repos: List[str], all_repos: bool = False, shallow: bool = False
):
    backup_base = Path(backup_dir)
    if all_repos:
        if repos:
            raise ValueError("Do you want specific repos or all repos? Make up your mind!")
        repos = list(pipeline.tasks)
    looked_up = [(spec, lookup_dotted(pipeline, spec)) for spec in repos]
    new_repos: Dict[str, repomodule.Repository] = {}
    for name, task_or_repo in looked_up:
        if isinstance(task_or_repo, repomodule.Repository):
            new_repos[name] = task_or_repo
        else:
            for link_name, link in task_or_repo.links.items():
                new_repos[f"{name}.{link_name}"] = link.repo
                for cokey_name, cokey in link.cokeyed.items():
                    new_repos[f"{name}.{link_name}.{cokey_name}"] = cokey

    # generate special names to unambiguously refer to repositories with no direct name
    # these names are only valid within backup and restore, for now
    if not shallow:
        for name, repo in list(new_repos.items()):
            footprint = list(repo.footprint())
            if len(footprint) == 1 and footprint[0] is repo:
                continue
            for i, footprint_repo in enumerate(footprint):
                footprint_name = f"{name}.__footprint.{i}"
                new_repos[footprint_name] = footprint_repo
            new_repos.pop(name)

    jobs = []
    canonical: Dict[repomodule.Repository, str] = {}

    for repo_name, repo in new_repos.items():
        if getattr(repo, "_EXCLUDE_BACKUP", False):
            continue

        repo_base = backup_base / repo_name

        if repo in canonical:
            if repo_base.is_symlink():
                repo_base.unlink()
            repo_base.symlink_to(canonical[repo])
            continue

        if isinstance(repo, repomodule.BlobRepository):
            new_repo_file = repo.construct_backup_repo(repo_base)
            await new_repo_file.validate()
            jobs.append(_repo_copy_blob(repo, new_repo_file))
        elif isinstance(repo, repomodule.MetadataRepository):
            new_repo_meta = repo.construct_backup_repo(repo_base)
            await new_repo_meta.validate()
            jobs.append(_repo_copy_meta(repo, new_repo_meta))
        elif isinstance(repo, repomodule.FilesystemRepository):
            new_repo_fs = repo.construct_backup_repo(repo_base)
            await new_repo_fs.validate()
            jobs.append(_repo_copy_fs(repo, new_repo_fs))
        else:
            print("Warning: cannot backup", repo_name, "because it is of unknown type", repo)
            continue
        canonical[repo] = repo_name

    await asyncio.gather(*jobs)


async def action_restore(pipeline: Pipeline, backup_dir: str, repos: List[str], all_repos: bool = False):
    backup_base = Path(backup_dir)

    if all_repos:
        if repos:
            raise ValueError("Do you want specific repos or all repos? Make up your mind!")
        repos = [p.name for p in backup_base.iterdir()]

    jobs = []
    seen = set()
    for repo_path in repos:
        repo_base = backup_base / repo_path
        try:
            repo = lookup_dotted(pipeline, repo_path, True)
        except KeyError as e:
            print("Warning: cannot restore", repo_path, "because I can't find", e.args[0])
            continue
        if repo in seen:
            continue
        seen.add(repo)
        compress = next(repo_base.iterdir(), Path("")).name.endswith(".gz")
        if isinstance(repo, repomodule.BlobRepository):
            new_repo_file = repo.construct_backup_repo(repo_base, force_compress=compress)
            await new_repo_file.validate()
            jobs.append(_repo_copy_blob(new_repo_file, repo))
        elif isinstance(repo, repomodule.MetadataRepository):
            new_repo_meta = repo.construct_backup_repo(repo_base, force_compress=compress)
            await new_repo_meta.validate()
            jobs.append(_repo_copy_meta(new_repo_meta, repo))
        elif isinstance(repo, repomodule.FilesystemRepository):
            new_repo_fs = repo.construct_backup_repo(repo_base, force_compress=compress)
            await new_repo_fs.validate()
            jobs.append(_repo_copy_fs(new_repo_fs, repo))
        else:
            print("Warning: cannot restore", repo_path, "because it is of unknown type", repo)

    await asyncio.gather(*jobs)


async def _repo_copy_blob(repo_src: repomodule.BlobRepository, repo_dst: repomodule.BlobRepository):
    async for ident in repo_src:
        async with await repo_src.open(ident, "rb") as fp_r, await repo_dst.open(ident, "wb") as fp_w:
            await async_copyfile(fp_r, fp_w)


async def _repo_copy_meta(repo_src: repomodule.MetadataRepository, repo_dst: repomodule.MetadataRepository):
    for ident, data in (await repo_src.info_all()).items():
        await repo_dst.dump(ident, data)


async def _repo_copy_fs(repo_src: repomodule.FilesystemRepository, repo_dst: repomodule.FilesystemRepository):
    # probably want to specify something about whether to use dump or dump tarball
    def make_writer(repo_src, ident, queue):
        async def write_then_close():
            await repo_src.get_tarball(ident, queue)
            queue.close()

        return write_then_close

    async for ident in repo_src:
        queue = AsyncQueueStream()

        await asyncio.gather(repo_dst.dump_tarball(ident, queue), make_writer(repo_src, ident, queue)())


def fuse_stub(*args, **kwargs):
    print("Please pip install pydatafs in order to use pd fuse")
    print("Note that this requires operating system dependencies, probably libfuse3-dev and fuse3")
    return 1


async def why_ready(pipeline: Pipeline, task: str):
    ready = pipeline.tasks[task].ready
    assert isinstance(ready, repomodule.BlockingRepository)
    source = ready.source
    assert isinstance(source, repomodule.AggregateAndRepository)
    unless = ready.unless
    assert isinstance(unless, repomodule.AggregateOrRepository)

    print("ready", " ".join(await ready.keys()))
    print("")
    print("### SOURCE")
    for name, repo in source.children.items():
        print(name, " ".join(await repo.keys()))
    print("")
    print("### UNLESS")
    for name, repo in unless.children.items():
        print(name, " ".join(await repo.keys()))
