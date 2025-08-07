"""A Task is a unit of execution which can act on multiple repositories.

You define a task by instantiating a Task subclass and passing it to a Pipeline object.

Tasks are related to Repositories by Links. Links are created by
``Task.link("my_link_name", my_repository, LinkKind.Something)``. See `Task.link` for more information.

.. autodata:: STDOUT
"""

from __future__ import annotations

from typing import (
    Any,
    Awaitable,
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    Union,
    cast,
)
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import FIRST_EXCEPTION
from concurrent.futures import Executor as FuturesExecutor
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
import asyncio
import copy
import inspect
import json
import logging
import math
import os
import random
import shlex
import string
import sys
import traceback

import aiofiles.os
import jinja2.async_utils
import jinja2.compiler
import sonyflake
import yaml

from pydatatask.host import LOCAL_HOST, Host, HostOS
import pydatatask

from . import executor as execmodule
from . import repository as repomodule
from .quota import Quota, _MaxQuotaType
from .utils import (
    STDOUT,
    AReadStreamBase,
    AsyncReaderQueueStream,
    _StderrIsStdout,
    crypto_hash,
    safe_load,
    supergetattr,
    supergetattr_path,
)

l = logging.getLogger(__name__)

__all__ = (
    "LinkKind",
    "Link",
    "Task",
    "KubeTask",
    "ProcessTask",
    "InProcessSyncTask",
    "ExecutorTask",
    "KubeFunctionTask",
    "ContainerTask",
    "STDOUT",
)

# pylint: disable=broad-except,bare-except


@dataclass
class TemplateInfo:
    """The data necessary to assemble a template including a link argument."""

    arg: Any
    preamble: Optional[Any] = None
    epilogue: Optional[Any] = None
    file_host: Optional[Host] = None


idgen = sonyflake.SonyFlake()


async def render_template(template, template_env: Dict[str, Any]):
    """Given a template and an environment, use jinja2 to parameterize the template with the environment.

    :param template: A template string, or a path to a local template file.
    :param template_env: A mapping from environment key names to values.
    :return: The rendered template, as a string.
    """
    j = jinja2.Environment(
        undefined=jinja2.StrictUndefined,
        enable_async=True,
        keep_trailing_newline=True,
    )

    def shquote(s):
        return shlex.quote(str(s))

    j.filters["shquote"] = shquote
    j.filters["to_yaml"] = yaml.safe_dump
    j.filters["to_json"] = json.dumps
    j.code_generator_class = ParanoidAsyncGenerator
    templating = j.from_string(template)
    try:
        return await templating.render_async(**template_env)
    except Exception as e:
        if await aiofiles.os.path.isfile(template):
            raise ValueError(template + " generated an exception") from e
        raise ValueError("The following template generated an exception:\n" + template) from e


def _read_template(template) -> str:
    if os.path.isfile(template):
        with open(template, "r", encoding="utf-8") as fp:
            return fp.read()
    else:
        return template


class LinkKind(Enum):
    """The way a given link should be made available as a template parameter."""

    InputRepo = auto()
    InputId = auto()
    InputMetadata = auto()
    InputFilepath = auto()
    OutputRepo = auto()
    OutputId = auto()
    OutputFilepath = auto()
    StreamingOutputFilepath = auto()
    StreamingInputFilepath = auto()
    RequestedInput = auto()


INPUT_KINDS: Set[LinkKind] = {
    LinkKind.InputId,
    LinkKind.InputMetadata,
    LinkKind.InputFilepath,
    LinkKind.InputRepo,
    LinkKind.StreamingInputFilepath,
    LinkKind.RequestedInput,
}
OUTPUT_KINDS: Set[LinkKind] = {
    LinkKind.OutputId,
    LinkKind.OutputFilepath,
    LinkKind.OutputRepo,
    LinkKind.StreamingOutputFilepath,
}


@dataclass
class Link:
    """The dataclass for holding linked repositories and their disposition metadata.

    Don't create these manually, instead use `Task.link`.
    """

    repo: "repomodule.Repository"
    kind: Optional[LinkKind]
    key: Optional[Union[str, Callable[[str], Awaitable[str]]]]
    key_footprint: List["repomodule.Repository"]
    cokeyed: Dict[str, "repomodule.Repository"]
    auto_meta: Optional[str]
    auto_values: Optional[Any]
    is_input: bool
    is_output: bool
    is_status: bool
    inhibits_start: bool
    required_for_start: Union[bool, str]
    inhibits_output: bool
    required_for_success: bool
    force_path: Optional[str]
    DANGEROUS_filename_is_key: bool
    content_keyed_md5: bool
    equals: Optional[str] = None


class Task(ABC):
    """The Task base class."""

    def __init__(
        self,
        name: str,
        done: "repomodule.MetadataRepository",
        ready: Optional["repomodule.Repository"] = None,
        disabled: bool = False,
        failure_ok: bool = False,
        long_running: bool = False,
        timeout: Optional[timedelta] = None,
        queries: Optional[Dict[str, pydatatask.query.query.Query]] = None,
        replicable: bool = False,
        max_replicas: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        self.name = name
        self._ready = ready
        self.links: Dict[str, Link] = {}
        self.synchronous = False
        self.metadata = True
        self.debug_trace = False
        self.require_success = False
        self.disabled = disabled
        self.agent_url = ""
        self.agent_secret = ""
        self._related_cache: Dict[str, Any] = {}
        self._filtered_cache: Dict[Tuple[str, str], Any] = {}
        self.long_running = long_running
        self.global_template_env: Dict[str, Any] = {}
        self.annotations: Dict[str, str] = {}
        self.fail_fast = False
        self.timeout = timeout
        self.queries = queries or {}
        self.done = done
        self.failure_ok = failure_ok
        self.replicable = replicable
        self.max_replicas = max_replicas
        self.success = pydatatask.query.repository.QueryMetadataRepository(
            "done.filter[.getsuccess]()", {"success": pydatatask.query.parser.QueryValueType.Bool}, {"done": done}
        )
        self._max_quota: Optional[Quota] = None
        self.max_concurrent_jobs: Optional[int] = None
        self.max_spawn_jobs = 100
        self.max_spawn_jobs_period = timedelta(minutes=1)
        self.cache_dir = cache_dir

        self.link(
            "done",
            done,
            None,
            is_status=True,
            inhibits_start=True,
            required_for_success=failure_ok,
        )

        self.link(
            "success",
            self.success,
            None,
            is_status=True,
            required_for_success=not failure_ok,
        )

    def __repr__(self):
        return f"<{type(self).__name__} {self.name}>"

    def cache_flush(self):
        """Flush any in-memory caches."""
        self._related_cache.clear()
        self._filtered_cache.clear()
        for link in self.links.values():
            link.repo.cache_flush()
        if self._ready is not None:
            self._ready.cache_flush()

    @property
    @abstractmethod
    def job_quota(self) -> Quota:
        """The resources requested by a single job instance."""
        raise NotImplementedError

    @property
    def fallback_quota(self) -> Optional[Quota]:
        return None

    @property
    @abstractmethod
    def resource_limit(self) -> Quota:
        """The total resources available for allocation to this job.

        This object may be shared by reference among multiple jobs.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def host(self) -> Host:
        """Return the host which will eventually execute the task.

        This is used to determine what resources will and will not be available locally during task execution.
        """
        raise NotImplementedError

    def mktemp(self, identifier: str) -> str:
        """Generate a temporary filepath for the task host system."""
        return self.host.mktemp(identifier)

    def mk_error_handler(self, agent_url, headers):
        """Generate a script which should handle an error for the given agent URL."""
        splitsies = agent_url.split("://", 1)
        if len(splitsies) == 1:
            (domainpath,) = splitsies
        else:
            _, domainpath = splitsies
        _, path = domainpath.split("/", 1)
        return self.host.mk_http_get("/dev/stderr", f"{self.agent_url}/errors/{path}", headers)

    def mk_http_get(
        self, filename: str, url: str, headers: Dict[str, str], handle_err: str = "", cache_key: Optional[str] = None
    ) -> Any:
        """Generate logic to perform an http download for the task host system.

        For shell script-based tasks, this will be a shell script, but for other tasks it may be other objects.
        """
        get = self.host.mk_http_get(filename, url, headers, verbose=self.debug_trace, handle_err=handle_err)
        if self.cache_dir is not None and cache_key is not None:
            return self.host.mk_cache_get_static(filename, cache_key, get, self.cache_dir)
        return get

    def mk_http_post(
        self,
        filename: str,
        url: str,
        headers: Dict[str, str],
        output_filename: Optional[str] = None,
        required_for_success: bool = True,
    ) -> Any:
        """Generate logic to perform an http upload for the task host system.

        For shell script-based tasks, this will be a shell script, but for other tasks it may be other objects.
        """
        return self.host.mk_http_post(
            filename, url, headers, output_filename, verbose=self.debug_trace, required_for_success=required_for_success
        )

    def mk_repo_get(self, filename: str, link_name: str, job: str, cache_key: Optional[str] = None) -> Any:
        """Generate logic to perform an repository download for the task host system.

        For shell script-based tasks, this will be a shell script, but for other tasks it may be other objects.
        """
        is_filesystem = isinstance(self.links[link_name].repo, repomodule.FilesystemRepository)
        payload_filename = self.mktemp(job + "-zip") if is_filesystem else filename
        url = f"{self.agent_url}/data/{self.name}/{link_name}/{job}"
        headers = {"Cookie": "secret=" + self.agent_secret}
        result = self.host.mk_http_get(
            payload_filename,
            url,
            headers,
            verbose=self.debug_trace,
            handle_err=self.mk_error_handler(url, headers),
        )
        if self.cache_dir is not None and cache_key is not None:
            result = self.host.mk_cache_get_static(payload_filename, cache_key, result, self.cache_dir)
        if is_filesystem:
            result += self.host.mk_unzip(filename, payload_filename)
        return result

    def mk_repo_put(
        self, filename: str, link_name: str, job: str, hostjob: Optional[str] = None, bypass_dangerous: bool = False
    ) -> Any:
        """Generate logic to perform an repository insert for the task host system.

        For shell script-based tasks, this will be a shell script, but for other tasks it may be other objects.
        """
        is_filesystem = isinstance(self.links[link_name].repo, repomodule.FilesystemRepository)
        payload_filename = self.mktemp(job + "-zip") if is_filesystem else filename
        url = f"{self.agent_url}/data/{self.name}/{link_name}/$UPLOAD_JOB" + (
            f"?hostjob={hostjob}" if hostjob is not None else ""
        )
        headers = {"Cookie": "secret=" + self.agent_secret}

        content_keyed_md5 = self.links[link_name].content_keyed_md5
        DANGEROUS_filename_is_key = self.links[link_name].DANGEROUS_filename_is_key
        assert not (
            content_keyed_md5 and DANGEROUS_filename_is_key
        ), "content_keyed_md5 and DANGEROUS_filename_is_key are mutually exclusive"
        if self.links[link_name].content_keyed_md5:
            result = f"UPLOAD_JOB=$(md5sum {filename} | cut -d' ' -f1)\n"
        elif self.links[link_name].DANGEROUS_filename_is_key and not bypass_dangerous:
            result = f"UPLOAD_JOB=$(basename {filename})\n"
        else:
            result = f"UPLOAD_JOB={job}\n"
        result += self.host.mk_http_post(
            payload_filename,
            url,
            headers,
            verbose=self.debug_trace,
            handle_err=self.mk_error_handler(url, headers),
            required_for_success=self.links[link_name].required_for_success,
        )
        if is_filesystem:
            result = self.host.mk_zip(payload_filename, filename) + result
        return result

    def mk_query_function(self, query_name: str) -> Tuple[Any, Any]:
        """Generate a shell function (???

        abstraction leak) for the given query.
        """
        parameters = self.queries[query_name].parameters
        url = f"{self.agent_url}/query/{self.name}/{query_name}"
        headers = {"Cookie": "secret=" + self.agent_secret}
        return (
            f"""
        query_{query_name}() {{
            INPUT_FILE=$(mktemp)
            while [ -n "$1" ]; do
                case "$1" in
                    {" ".join(f'--{p}) echo "{p}: $2">>$INPUT_FILE ;;' for p in parameters)}
                    *) echo "Bad query parameter $1" >&2; exit 1 ;;
                esac
                shift 2
            done
            {self.host.mk_http_post(
                "$INPUT_FILE",
                url,
                headers,
                "/dev/stdout",
                verbose=self.debug_trace,
                required_for_success=False,
            )}
            rm $INPUT_FILE
        }}
        """,
            f"query_{query_name}",
        )

    def mk_download_function(self, link_name: str) -> Tuple[Any, Any]:
        """Generate a shell function (???

        abstraction leak) to download a parameterized entry from the given repository.
        """
        return (
            f"""
        download_{link_name}() {{
            {self.mk_repo_get("/dev/stdout", link_name, "$1")}
        }}
        """,
            f"download_{link_name}",
        )

    def mk_repo_put_cokey(
        self, filename: str, link_name: str, cokey_name: str, job: str, hostjob: Optional[str] = None
    ) -> Any:
        """Generate logic to upload a cokeyed link."""
        is_filesystem = isinstance(self.links[link_name].cokeyed[cokey_name], repomodule.FilesystemRepository)
        payload_filename = self.mktemp(job + "-zip") if is_filesystem else filename
        url = f"{self.agent_url}/cokeydata/{self.name}/{link_name}/{cokey_name}/{job}" + (
            f"?hostjob={hostjob}" if hostjob is not None else ""
        )
        headers = {"Cookie": "secret=" + self.agent_secret}
        result = self.host.mk_http_post(
            payload_filename,
            url,
            headers,
            verbose=self.debug_trace,
            required_for_success=self.links[link_name].required_for_success,
        )
        if is_filesystem:
            result = self.host.mk_zip(payload_filename, filename) + result
        return result

    def mk_mkdir(self, filepath: str) -> Any:
        """Generate logic to perform a directory creation for the task host system.

        For shell script-based tasks, this will be a shell script, but for other tasks it may be other objects.
        """
        return self.host.mk_mkdir(filepath)

    def mk_watchdir_upload(
        self,
        filepath: str,
        link_name: str,
        hostjob: Optional[str],
        force_upload_dir: Optional[str] = None,
        mkdir: bool = True,
        DANGEROUS_filename_is_key: bool = False,
        content_keyed_md5: bool = False,
    ) -> Tuple[Any, Any, Dict[str, str]]:
        """Misery and woe.

        If you're trying to debug something and you run across this, just ask rhelmot for help.
        """
        # leaky abstraction!
        if self.host.os != HostOS.Linux:
            raise ValueError("Not sure how to do this off of linux")
        upload = self.host.mktemp("upload") if force_upload_dir is None else force_upload_dir
        scratch = self.host.mktemp("scratch")
        finished = self.host.mktemp("finished")
        lock = self.host.mktemp("lock")
        cokeyed = {name: self.host.mktemp(name) for name in self.links[link_name].cokeyed}
        dict_result: Dict[str, Any] = {}
        dict_result["main_dir"] = filepath
        dict_result["lock_dir"] = lock
        dict_result["uploaded_dir"] = scratch
        dict_result["cokeyed_dirs"] = cokeyed
        dict_result["cokeyed"] = cokeyed
        # auto_values = self.links[link_name].auto_values is not None
        auto_cokey = self.links[link_name].auto_meta
        nonce = "".join(random.choice(string.ascii_lowercase) for _ in range(10))

        def prep_upload(cokey, cokeydir):
            if auto_cokey == cokey:
                return f'(test -e "{cokeydir}/$f" && ln -s "{cokeydir}/$f" {upload} || touch {upload}) && '
            else:
                return f"ln -s {cokeydir}/$f {upload}"

        idgen_function = f"""
        idgen_{nonce}() {{
          echo $(($(shuf -i0-255 -n1) +
                  $(shuf -i0-255 -n1)*0x100 +
                  $(shuf -i0-255 -n1)*0x10000 +
                  $(shuf -i0-255 -n1)*0x1000000 +
                  $(shuf -i0-255 -n1)*0x100000000 +
                  $(shuf -i0-255 -n1)*0x10000000000 +
                  $(shuf -i0-255 -n1)*0x1000000000000 +
                  $(shuf -i0-127 -n1)*0x100000000000000))
        }}
        """
        assert not (
            DANGEROUS_filename_is_key and content_keyed_md5
        ), "DANGEROUS_filename_is_key and content_keyed_md5 are mutually exclusive"
        if DANGEROUS_filename_is_key:
            idgen_function = f"""
            idgen_{nonce}() {{
                f="$1"
                echo $(basename "$f")
            }}
            """
        elif content_keyed_md5:
            idgen_function = f"""
            idgen_{nonce}() {{
                f="$1"
                echo $(md5sum "$f" | cut -d' ' -f1)
            }}
            """

        templated_preamble = f"""
        {self.host.mk_mkdir(filepath) if mkdir else ""}
        {self.host.mk_mkdir(scratch)}
        {self.host.mk_mkdir(lock)}
        {'; '.join(self.host.mk_mkdir(cokey_dir) for cokey_dir in cokeyed.values())}
        {idgen_function}
        watcher_{nonce}() {{
          set +x
          WATCHER_LAST=
          while ! [ -d {filepath} ]; do
            sleep 1
          done
          cd {filepath}
          while [ -z "$WATCHER_LAST" ]; do
            sleep 5
            if [ -f {finished} ]; then
                WATCHER_LAST=1
            fi
            for f in *; do
              if [ -e "$f" ] && ! [ -e "{scratch}/$f" ] && ! [ -e "{lock}/$f" ] && [ "$(($(date +%s) - $(stat -c %Y "$f")))" -ge 5 ]; then
                ID=$(idgen_{nonce} "$f")
                ln -sf "$PWD/$f" {upload}
                {self.mk_repo_put(upload, link_name, "$ID", hostjob, bypass_dangerous=True)}
                rm {upload}
                {'; '.join(
                  f'{prep_upload(cokey, cokeydir)}'
                  f'({self.mk_repo_put_cokey(upload, link_name, cokey, "$ID", hostjob)}); '
                  f'rm {upload}'
                  for cokey, cokeydir
                  in cokeyed.items())}
                echo $ID >"{scratch}/$f"
              fi
            done
          done
        }}
        watcher_{nonce} &
        WATCHER_PID_{nonce}=$!
        """

        templated_epilogue = f"""
        echo "Finishing up"
        echo 1 >{finished}
        wait $WATCHER_PID_{nonce}
        """

        return templated_preamble, templated_epilogue, dict_result

    def mk_watchdir_download(self, filepath: str, link_name: str, job: str) -> Any:
        """Misery and woe.

        If you're trying to debug something and you run across this, just ask rhelmot for help.
        """
        # leaky abstraction!
        if self.host.os != HostOS.Linux:
            raise ValueError("Not sure how to do this off of linux")
        scratch = self.host.mktemp("scratch")
        download = self.host.mktemp("download")
        lock = self.host.mktemp("lock")
        stream_url = f"{self.agent_url}/stream/{self.name}/{link_name}/{job}"
        stream_headers = {"Cookie": f"secret={self.agent_secret}"}
        nonce = "".join(random.choice(string.ascii_lowercase) for _ in range(10))

        templated_preamble = f"""
        {self.host.mk_mkdir(filepath)}
        {self.host.mk_mkdir(scratch)}
        {self.host.mk_mkdir(lock)}
        watcher_{nonce}() {{
            set +x
            cd {filepath}
            while true; do
                sleep 5
                {self.mk_http_get(download, stream_url, stream_headers, handle_err=self.mk_error_handler(stream_url, stream_headers))}
                for ID in $(cat {download}); do
                    if ! [ -e "{scratch}/$ID" ]; then
                        touch {lock}/$ID
                        {self.mk_repo_get(download, link_name, "$ID")}
                        mv {download} $ID
                        echo >{scratch}/$ID
                        rm {lock}/$ID
                    fi
                done
            done
        }}
        watcher_{nonce} &
        """

        return templated_preamble, {
            "main_dir": filepath,
            "lock_dir": lock,
            "download_file": download,
        }

    def _make_ready(self):
        """Return the repository whose job membership is used to determine whether a task instance should be
        launched.

        If an override is not provided to the constructor, this is that, otherwise it is
        ``AND(*requred_for_start, NOT(OR(*inhibits_start)))``.
        """
        base_listing = []
        scoped_listing = defaultdict(list)
        for link_name, (repo, scope) in self.required_for_start.items():
            if scope is True:
                base_listing.append((link_name, repo))
            else:
                scoped_listing[scope].append((link_name, repo))
        for scope, scope_listing in scoped_listing.items():
            if len(scope_listing) > 1:
                base_listing.append((str(scope), repomodule.AggregateOrRepository(**dict(scope_listing))))
            else:
                base_listing.append(scope_listing[0])

        return repomodule.BlockingRepository(
            repomodule.AggregateAndRepository(**dict(base_listing)),
            repomodule.AggregateOrRepository(**self.inhibits_start),
        )

    def derived_hash(self, job: str, link_name: str, along: bool = True) -> str:
        """For allocate-key links, determine the allocated job id.

        If along=False, determine the input job id which produced the allocated job id.
        """
        hashed = crypto_hash([self.name, link_name, self.links[link_name].repo])
        sign = 1 if along else -1
        if job.isdigit() and 0 <= int(job) < 2**64:
            return str((int(job) + sign * hashed) % 2**64)
        if all(c in string.hexdigits for c in job) and len(job) % 2 == 0:
            bytesjob = bytes.fromhex(job)
            intjob = int.from_bytes(bytesjob, "big")
            length = len(bytesjob)
            modulus = 2 ** (len(bytesjob) * 8)
            return ((intjob + sign * hashed) % modulus).to_bytes(length, "big").hex()
        raise ValueError("Fatal: Job must be structured (long decimal or arbitrary hex) to derive a hash")

    def link(
        self,
        name: str,
        repo: "repomodule.Repository",
        kind: Optional[LinkKind],
        key: Optional[Union[str, Callable[[str], Awaitable[str]]]] = None,
        key_footprint: Optional[Iterable["repomodule.Repository"]] = None,
        cokeyed: Optional[Dict[str, "repomodule.Repository"]] = None,
        auto_meta: Optional[str] = None,
        auto_values: Optional[Any] = None,
        is_input: Optional[bool] = None,
        is_output: Optional[bool] = None,
        is_status: Optional[bool] = None,
        inhibits_start: Optional[bool] = None,
        required_for_start: Optional[Union[bool, str]] = None,
        inhibits_output: Optional[bool] = None,
        required_for_success: Optional[bool] = None,
        force_path: Optional[str] = None,
        DANGEROUS_filename_is_key: bool = False,
        content_keyed_md5: bool = False,
        equals: Optional[str] = None,
    ):
        """Create a link between this task and a repository.

        All the nullable paramters have their defaults picked based on other parameters.

        :param name: The name of the link. Used during templating.
        :param repo: The repository to link.
        :param kind: The way to transform this repository during templating.
        :param key: A related item from a different link to use instead of the current job when doing repository lookup.
            Or, a function taking the task's job and producing the desired job to do a lookup for.
        :param cokeyed: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
        :param auto_meta: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.
        :param auto_values: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC.
        :param is_input: Whether this repository contains data which is consumed by the task. Default based on kind.
        :param is_output: Whether this repository is populated by the task. Default based on kind.
        :param is_status: Whether this task is populated with task-ephemeral data. Default False.
        :param inhibits_start: Whether membership in this repository should be used in the default ``ready`` repository
            to prevent jobs for being launched. Default False.
        :param required_for_start: Whether membership in this repository should be used in the default ``ready``
            repository to allow jobs to be launched. If unspecified, defaults to ``is_input``.
        :param inhibits_output: Whether this repository should become ``inhibits_start`` in tasks this task is plugged
            into. Default False.
        :param required_for_success: Whether this repository should become `required_for_start` in tasks this task is
            plugged into.
        """
        if is_input is None:
            is_input = kind in INPUT_KINDS
            if required_for_start is None and kind in (LinkKind.StreamingInputFilepath, LinkKind.RequestedInput):
                required_for_start = False
        if is_output is None:
            is_output = kind in OUTPUT_KINDS
        if is_status is None:
            is_status = False
        if required_for_start is None:
            required_for_start = is_input
        if inhibits_start is None:
            inhibits_start = False
        if required_for_success is None:
            required_for_success = False
        if inhibits_output is None:
            inhibits_output = False
        if key == "ALLOC" and is_input:
            raise ValueError("Link cannot be allocated key and input")

        self.links[name] = Link(
            repo=repo,
            key=key,
            key_footprint=list(key_footprint or ()),
            kind=kind,
            cokeyed=cokeyed or {},
            auto_meta=auto_meta,
            auto_values=auto_values,
            is_input=is_input,
            is_output=is_output,
            is_status=is_status,
            inhibits_start=inhibits_start,
            required_for_start=required_for_start,
            inhibits_output=inhibits_output,
            required_for_success=required_for_success,
            force_path=force_path,
            DANGEROUS_filename_is_key=DANGEROUS_filename_is_key,
            content_keyed_md5=content_keyed_md5,
            equals=equals,
        )

    def _repo_related(self, linkname: str, seen: Optional[Set[str]] = None) -> "repomodule.Repository":
        if linkname in self._related_cache:
            return self._related_cache[linkname]

        if seen is None:
            seen = set()
        if linkname in seen:
            raise ValueError("Infinite recursion in repository related key lookup")
        link = self.links[linkname]
        if link.kind == LinkKind.StreamingInputFilepath:

            async def filterer(job: str) -> bool:
                stream = self._repo_filtered(job, linkname)
                async for _ in stream:
                    return True
                return False

            return repomodule.FilterRepository(
                repomodule.AggregateAndRepository(**self.required_for_start_basic),
                filterer,
            )
        if link.key is None:
            return link.repo

        if link.key == "ALLOC":
            mapped: repomodule.MetadataRepository = repomodule.FunctionCallMetadataRepository(
                lambda job: self.derived_hash(job, linkname),
                repomodule.AggregateAndRepository(**self.required_for_start_basic),
                [],
            )
            prefetch_lookup = False

        elif callable(link.key):
            mapped = repomodule.FunctionCallMetadataRepository(
                link.key, repomodule.AggregateAndRepository(**self.required_for_start_basic), link.key_footprint
            )
            prefetch_lookup = False
        else:
            splitkey = link.key.split(".")
            related = self._repo_related(splitkey[0], seen)
            if not isinstance(related, repomodule.MetadataRepository):
                raise TypeError("Cannot do key lookup on repository which is not MetadataRepository")

            async def mapper(_job, info):
                try:
                    return str(supergetattr_path(info, splitkey[1:]))
                except:
                    return ""

            mapped = related.map(mapper, [])
            prefetch_lookup = True

        if isinstance(link.repo, repomodule.MetadataRepository):
            result: repomodule.Repository = repomodule.RelatedItemMetadataRepository(
                link.repo, mapped, prefetch_lookup=prefetch_lookup
            )
        else:
            result = repomodule.RelatedItemRepository(link.repo, mapped, prefetch_lookup=prefetch_lookup)

        if isinstance(result, repomodule.MetadataRepository) and not isinstance(
            result, repomodule.CacheInProcessMetadataRepository
        ):
            result = repomodule.CacheInProcessMetadataRepository(result)
        self._related_cache[linkname] = result
        return result

    def _repo_filtered(self, job: str, linkname: str) -> "repomodule.Repository":
        if (job, linkname) in self._filtered_cache:
            return self._filtered_cache[(job, linkname)]

        link = self.links[linkname]
        if link.kind != LinkKind.StreamingInputFilepath:
            raise TypeError("Cannot automatically produce a filtered repo unless it's StreamingInput")
        if link.key is None:
            return link.repo
        if link.key == "ALLOC" or callable(link.key):
            raise TypeError(
                f"Bad key for repository filter: {link.key=!r} for {linkname=!r} in {self.name!r} for {job!r}"
            )

        splitkey = link.key.split(".")
        related = self.links[splitkey[0]].repo
        if not isinstance(related, repomodule.MetadataRepository):
            raise TypeError("Cannot do key lookup on repository which is not MetadataRepository")

        async def mapper(_job, info):
            return str(supergetattr_path(info, splitkey[1:]))

        mapped = related.map(mapper, [])

        if link.equals is not None:
            splitkey2 = link.equals.split(".")
            related2 = self._repo_related(splitkey2[0])
            if not isinstance(related2, repomodule.MetadataRepository):
                raise TypeError("Cannot do key lookup on repository which is not MetadataRepository")

            async def mapper2(_job, info):
                return str(supergetattr_path(info, splitkey2[1:]))

            mapped2 = related2.map(mapper2, [])
        else:
            mapped2 = None

        async def filterer(subjob: str) -> bool:
            try:
                if mapped2 is None:
                    mapped2_info = job
                else:
                    mapped2_info = await mapped2.info(job)
                mapped1_info = await mapped.info(subjob)
            except KeyError:
                return False
            return mapped1_info == mapped2_info

        if isinstance(link.repo, repomodule.MetadataRepository):
            r = repomodule.FilterMetadataRepository(link.repo, filterer)
        elif isinstance(link.repo, repomodule.FilesystemRepository):
            r = repomodule.FilterFilesystemRepository(link.repo, filterer)
        elif isinstance(link.repo, repomodule.BlobRepository):
            r = repomodule.FilterBlobRepository(link.repo, filterer)
        else:
            r = repomodule.FilterRepository(link.repo, filterer)
        self._filtered_cache[(job, linkname)] = r
        return r

    @property
    def ready(self):
        """Return the repository whose job membership is used to determine whether a task instance should be
        launched.

        If an override is provided to the constructor, this is that, otherwise it is
        ``AND(*requred_for_start, NOT(OR(*inhibits_start)))``.
        """
        if self._ready is None:
            self._ready = self._make_ready()
        return self._ready

    @property
    def input(self):
        """A mapping from link name to repository for all links marked ``is_input``."""
        result = {name: self._repo_related(name) for name, link in self.links.items() if link.is_input}
        if not result:
            raise ValueError("Every task must have at least one input")
        return result

    @property
    def output(self):
        """A mapping from link name to repository for all links marked ``is_output``."""
        return {name: self._repo_related(name) for name, link in self.links.items() if link.is_output}

    @property
    def inhibits_start(self):
        """A mapping from link name to repository for all links marked ``inhibits_start``."""
        return {name: self._repo_related(name) for name, link in self.links.items() if link.inhibits_start}

    @property
    def required_for_start(self):
        """A mapping from link name to repository for all links marked ``required_for_start``."""
        return {
            name: (self._repo_related(name), link.required_for_start)
            for name, link in self.links.items()
            if link.required_for_start
        }

    @property
    def required_for_start_basic(self):
        """A mapping from link name to repository for all links which must be populated in order to start the
        task."""
        return {
            name: self._repo_related(name)
            for name, link in self.links.items()
            if link.required_for_start is True and link.kind != LinkKind.StreamingInputFilepath
        }

    @property
    def inhibits_output(self):
        """A mapping from link name to repository for all links marked ``inhibits_output``."""
        return {name: self._repo_related(name) for name, link in self.links.items() if link.inhibits_output}

    @property
    def required_for_success(self):
        """A mapping from link name to repository for all links marked ``required_for_success``."""
        return {name: self._repo_related(name) for name, link in self.links.items() if link.required_for_success}

    async def validate(self):
        """Raise an exception if for any reason the task is misconfigured.

        This is guaranteed to be called exactly once per pipeline, so it is safe to use for setup and initialization in
        an async context.
        """

    @abstractmethod
    async def update(self) -> Tuple[Dict[Tuple[str, int], datetime], Set[str], Set[str]]:
        """Part one of the pipeline maintenance loop. Override this to perform any maintenance operations on the set
        of live tasks. Typically, this entails reaping finished processes.

        Returns a tuple: The start time for any currently live replicas, and the set of jobs that were reaped in this
        update.
        """
        raise NotImplementedError

    @abstractmethod
    async def launch(self, job: str, replica: int):
        """Launch a particular replica of a particular job.

        Override this to begin execution of the provided job/replica. Error handling will be done for you.
        """
        raise NotImplementedError

    @abstractmethod
    async def kill(self, job: str, replica: int):
        """Kill a particular replica of a particular job.

        If this is the last replica, don't populate done.
        """
        raise NotImplementedError

    @abstractmethod
    async def killall(self):
        """Kill all running jobs."""
        raise NotImplementedError

    # This should almost certainly instead return a context manager returning a object wrapping the jinja environment,
    # the preamble, and the epilogue which cleans up the coroutines on close.
    async def build_template_env(
        self,
        orig_job: str,
        replica: int,
        env_src: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], List[Any], List[Any]]:
        """Transform an environment source into an environment according to Links.

        Returns the environment, a list of preambles, and a list of epilogues. These may be of any type depending on the
        task type.
        """
        if env_src is None:
            env_src = {}
        env_src.update(self.links)
        env_src["job"] = orig_job
        env_src["task"] = self.name
        env_src["replica"] = replica

        def subkey(items: List[str]):
            src = result[items[0]]
            for i, subkey in enumerate(items[1:]):
                try:
                    src = supergetattr(src, subkey)
                except KeyError as e:
                    raise Exception(f"Cannot access {'.'.join(items[:i+2])} during link subkeying") from e
            return src

        preamble = []
        epilogue = []

        result = dict(self.global_template_env)
        pending: DefaultDict[str, List[Tuple[str, Link]]] = defaultdict(list)
        for env_name, link in env_src.items():
            if not isinstance(link, Link):
                result[env_name] = link
                continue
            if link.kind is None:
                continue

            subjob = orig_job
            if link.key is not None and link.kind != LinkKind.StreamingInputFilepath:
                if link.key == "ALLOC":
                    subjob = self.derived_hash(orig_job, env_name)
                elif callable(link.key):
                    subjob = await link.key(orig_job)
                else:
                    items = link.key.split(".")
                    if items[0] in result:
                        subjob = str(subkey(items))
                    else:
                        pending[items[0]].append((env_name, link))
                        continue

            arg = self.instrument_arg(
                orig_job,
                await link.repo.template(subjob, self, link.kind, env_name, orig_job),
                link.kind,
            )
            result[env_name] = arg.arg
            if arg.preamble is not None:
                preamble.append(arg.preamble)
            if arg.epilogue is not None:
                epilogue.append(arg.epilogue)
            if env_name in pending:
                for env_name2, link in pending[env_name]:
                    assert isinstance(link.key, str)
                    assert link.kind is not None
                    subjob = str(subkey(link.key.split(".")))
                    arg = self.instrument_arg(
                        orig_job,
                        await link.repo.template(
                            subjob,
                            self,
                            link.kind,
                            env_name2,
                            orig_job,
                        ),
                        link.kind,
                    )
                    result[env_name2] = arg.arg
                    if arg.preamble is not None:
                        preamble.append(arg.preamble)
                    if arg.epilogue is not None:
                        epilogue.append(arg.epilogue)
                pending.pop(env_name)

        if pending:
            raise Exception(f"Cannot access {' and '.join(pending)} during link subkeying")

        for query_name in self.queries:
            a_preamble, a_func = self.mk_query_function(query_name)
            if a_preamble is not None:
                preamble.append(a_preamble)
            result[query_name] = a_func

        return result, preamble, epilogue

    # pylint: disable=unused-argument
    def instrument_arg(self, job: str, arg: TemplateInfo, kind: LinkKind) -> TemplateInfo:
        """Do any task-specific processing on a template argument.

        This is called during build_template_env on each link, after Repository.template() runs on it.
        """
        return arg

    async def instrument_dump(
        self, content: AReadStreamBase, link: str, cokey: Optional[str], job: str, hostjob: Optional[str]
    ) -> AReadStreamBase:
        """Called when data is injected from a task through a link (currently only throgh the agent).

        Should return either the original stream or a new stream which is derivative of the old stream's content. By
        default, it applies auto_meta link data for metadata repositories.
        """
        if self.links[link].auto_meta == cokey and self.links[link].auto_values is not None and hostjob is not None:
            # just assume it's yaml. this is fine.
            data_str = await content.read()
            data = safe_load(data_str)
            env, _, _ = await self.build_template_env(hostjob, 0)
            rendered = await self._render_auto_values(env, self.links[link].auto_values)
            if isinstance(rendered, dict):
                if data is None:
                    pass
                elif isinstance(data, dict):
                    rendered.update(data)
                else:
                    raise TypeError(f"Cannot combine auto-meta, bad types: dict and {type(data)}")
            elif isinstance(rendered, list):
                if data is None:
                    pass
                elif isinstance(data, list):
                    rendered.extend(data)
                else:
                    raise TypeError(f"Cannot combine auto-meta, bad types: list and {type(data)}")
            else:
                raise TypeError(f"Bad rendered auto-meta type: {type(rendered)}")

            for item in env.values():
                if asyncio.iscoroutine(item):
                    item.close()

            result = AsyncReaderQueueStream()
            result.write(yaml.safe_dump(rendered).encode())
            result.close()
            return result
        return content

    async def _test_auto_values(self, template_env: Dict[str, Any]):
        for link in self.links.values():
            if link.auto_values is not None:
                await self._render_auto_values(template_env, link.auto_values)

    async def _render_auto_values(self, template_env: Dict[str, Any], template: Any) -> Any:
        if isinstance(template, str):
            return safe_load(await render_template(template, template_env))
        elif isinstance(template, dict):
            return {k: await self._render_auto_values(template_env, v) for k, v in template.items()}
        elif isinstance(template, list):
            return [await self._render_auto_values(template_env, i) for i in template]
        else:
            return template


class TemplateShellTask(Task):
    """A task which templates a shell script to run."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.global_script_env = {}

    async def build_template_env(
        self,
        orig_job: str,
        replica: int,
        env_src: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], List[Any], List[Any]]:
        env, preamble, epilogue = await super().build_template_env(orig_job, replica, env_src)
        NEWLINE = "\n"
        shutdown_script = self.mktemp("shutdown_script")
        shutting_down = self.mktemp("shutting_down")
        preamble.insert(
            0,
            f"""
        export SHUTDOWN_SCRIPT={shutdown_script}
        export SHUTTING_DOWN={shutting_down}
        echo "export IN_SHUTDOWN_SCRIPT=1" >$SHUTDOWN_SCRIPT
        touch $SHUTDOWN_SCRIPT
        shutdown_func() {{
            touch $SHUTTING_DOWN
            echo "Shutting down now"
            set +e
            . $SHUTDOWN_SCRIPT
        }}
        sigterm_func() {{
            shutdown_func
            exit 1
        }}
        trap 'sigterm_func' TERM
        """,
        )
        preamble.insert(0, f"{NEWLINE.join(f'export {k}={v}' for k, v in self.global_script_env.items())}\n")
        preamble.insert(0, f"export PDT_AGENT_URL='{self.agent_url}'\n")
        preamble.insert(0, f"export PDT_AGENT_SECRET='{self.agent_secret}'\n")
        preamble.insert(0, f"export NPROC_VAL='{int(math.ceil(self.job_quota.cpu))}'\n")
        # microseconds per tenth of a second (linux CFS cpu-quota)
        preamble.insert(0, f"export CPU_QUOTA='{int(self.job_quota.cpu * 100000)}'\n")
        # bytes
        preamble.insert(0, f"export MEM_QUOTA='{int(self.job_quota.mem)}'\n")
        preamble.insert(0, f"export JOB_ID='{orig_job}'")
        preamble.insert(0, f"export TASK_NAME='{self.name}'")
        preamble.insert(0, f"export REPLICA_ID='{replica}'")
        if self.debug_trace:
            preamble.insert(0, "set -x\n")
        epilogue.append("shutdown_func")
        return env, preamble, epilogue

    def make_main_script(self, preamble: List[str], main: str, epilogue: List[str]) -> str:
        NEWLINE = "\n"
        return f"""
        set -e
        {NEWLINE.join(preamble)}
        set +e
        (
        set -e
        set -u
        {main}
        )
        RETCODE=$?
        ANY_UPLOADS_FAILED=0
        {NEWLINE.join(epilogue)}
        if [ $ANY_UPLOADS_FAILED -ne 0 ]; then
            echo "Some uploads failed. Exiting."
            exit 1
        fi
        exit $RETCODE
        """


class ParanoidAsyncGenerator(jinja2.compiler.CodeGenerator):
    """A class to instrument jinja2 to be more aggressive about awaiting objects and to cache their results.

    Probably don't use this directly.
    """

    def write_commons(self):
        self.writeline("from jinja2.async_utils import _common_primitives")
        self.writeline("import inspect")
        self.writeline("seen = {}")
        self.writeline("async def auto_await2(value):")
        self.writeline("    if type(value) in _common_primitives:")
        self.writeline("        return value")
        self.writeline("    if inspect.isawaitable(value):")
        self.writeline("        cached = seen.get(value)")
        self.writeline("        if cached is None:")
        self.writeline("            cached = await value")
        self.writeline("            seen[value] = cached")
        self.writeline("        return cached")
        self.writeline("    return value")
        super().write_commons()

    def visit_Name(self, node, frame):
        if self.environment.is_async:
            self.write("(await auto_await2(")

        super().visit_Name(node, frame)

        if self.environment.is_async:
            self.write("))")


class KubeTask(TemplateShellTask):
    """A task which runs a kubernetes pod.

    Will automatically link a `LiveKubeRepository` as "live" with
    ``inhibits_output, is_status``
    """

    def __init__(
        self,
        name: str,
        executor: "execmodule.Executor",
        template: Union[str, Path],
        logs: Optional["repomodule.BlobRepository"],
        done: "repomodule.MetadataRepository",
        timeout: Optional[timedelta] = None,
        long_running: bool = False,
        template_env: Optional[Dict[str, Any]] = None,
        ready: Optional["repomodule.Repository"] = None,
        queries: Optional[Dict[str, pydatatask.query.query.Query]] = None,
        failure_ok: bool = False,
        replicable: bool = False,
        max_replicas: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        """
        :param name: The name of the task.
        :param executor: The executor to use for this task.
        :param quota: A QuotaManager instance. Tasks launched will contribute to its quota and be denied if they would
            break the quota.
        :param template: YAML markup for a pod manifest template, either as a string or a path to a file.
        :param logs: Optional: A BlobRepository to dump pod logs to on completion. Linked as "logs" with
            ``is_status``.
        :param done: A MetadataRepository in which to dump some information about the pod's lifetime and
            termination on completion. Linked as "done" with ``inhibits_start, required_for_success, is_status``.
        :param timeout: Optional: When a pod is found to have been running continuously for this amount of time, it
            will be timed out and stopped.
        :param template_env:     Optional: Additional keys to add to the template environment.
        :param ready:   Optional: A repository from which to read task-ready status.
        """
        super().__init__(
            name,
            done,
            ready,
            long_running=long_running,
            timeout=timeout,
            queries=queries,
            failure_ok=failure_ok,
            replicable=replicable,
            max_replicas=max_replicas,
            cache_dir=cache_dir,
        )

        self.template = _read_template(template)
        self._executor = executor
        self._podman: Optional["execmodule.PodManager"] = None
        self.logs = logs
        self.template_env = template_env if template_env is not None else {}
        self.warned = False

        self.link(
            "live",
            repomodule.LiveKubeRepository(self),
            None,
            is_status=True,
            inhibits_output=True,
        )
        if logs:
            self.link(
                "logs",
                logs,
                None,
                is_status=True,
            )

    def cache_flush(self):
        super().cache_flush()
        if self._podman is not None:
            self._podman.cache_flush()

    @property
    def host(self):
        return self.podman.host

    @property
    def job_quota(self):
        try:
            manifest = safe_load(self.template)
        except Exception as e:
            raise Exception("KubeTask pod manfest template MUST parse as yaml WITHOUT templating") from e
        request = Quota.parse(0, 0)
        for container in manifest["spec"]["containers"]:
            request += Quota.parse(
                container["resources"]["requests"]["cpu"],
                container["resources"]["requests"]["memory"],
            )
        return request

    @property
    def resource_limit(self):
        return self.podman.quota

    @property
    def podman(self) -> execmodule.PodManager:
        """The pod manager instance for this task.

        Will raise an error if the manager is provided by an unopened session.
        """
        if self._podman is None:
            self._podman = self._executor.to_pod_manager()
        return self._podman

    async def build_template_env(self, orig_job, replica, env_src=None):
        if env_src is None:
            env_src = {}
        env_src.update(vars(self))
        env_src.update(self.template_env)
        template_env, preamble, epilogue = await super().build_template_env(orig_job, replica, env_src)
        template_env["argv0"] = os.path.basename(sys.argv[0])
        return template_env, preamble, epilogue

    async def launch(self, job, replica):
        template_env, preamble, epilogue = await self.build_template_env(job, replica)
        manifest = safe_load(await render_template(self.template, template_env))
        await self._test_auto_values(template_env)
        for item in template_env.values():
            if asyncio.iscoroutine(item):
                item.close()

        assert manifest["kind"] == "Pod"
        spec = manifest["spec"]
        spec["restartPolicy"] = "Never"

        for container in spec["containers"]:
            # horrible and incomplete
            command = container.pop("command", [])
            args = container.pop("args", [])
            execute = shlex.join(command + args)
            container["command"] = [
                "sh",
                "-c",
                self.make_main_script(preamble, execute, epilogue),
            ]

        await self.podman.launch(self.name, job, replica, manifest)

    async def kill(self, job: str, replica: int):
        await self.podman.kill(self.name, job, replica)

    async def killall(self):
        for pod in await self.podman.query(task=self.name):
            await self.podman.delete(pod)

    async def update(self):
        live, reaped = await self.podman.update(self.name, timeout=self.timeout)
        backoff = set()
        for job, replicas in reaped.items():
            success = True
            logs = {}
            dones = {}
            for replica, (log, done) in replicas.items():
                success &= done["success"] | (done["timeout"] and self.long_running)
                logs[replica] = log
                dones[str(replica)] = done

            if self.logs is not None:
                async with await self.logs.open(job, "wb") as fp:
                    if len(logs) == 1:
                        (log,) = logs.values()
                    else:
                        log = b"".join(f">>> replica {k} <<<\n".encode() + v for k, v in logs.items() if v is not None)
                    if log:
                        await fp.write(log)

            if not success and self.require_success and not self.fail_fast:
                l.error(
                    "require_success is set but %s:%s failed. job will be retried.",
                    self.name,
                    job,
                )
                backoff.add(job)
                continue

            if len(dones) == 1:
                (done,) = dones.values()
            else:
                done = {
                    "success": success,
                    "start_time": min(d["start_time"] for d in dones.values()),
                    "end_time": max(d["end_time"] for d in dones.values()),
                    "timeout": all(d["timeout"] for d in dones.values()),
                    "replicas_done": dones,
                }
            await self.done.dump(job, done)

            if not success and self.require_success:
                assert self.fail_fast
                raise Exception(f"require_success is set but {self.name}:{job} failed. fail_fast is set so aborting.")

        return live, set(reaped), backoff


class ProcessTask(TemplateShellTask):
    """A task that runs a script.

    The interpreter is specified by the shebang, or the default shell if none present. The execution environment for the
    task is defined by the ProcessManager instance provided as an argument.
    """

    def __init__(
        self,
        name: str,
        template: str,
        done: "repomodule.MetadataRepository",
        executor: Optional[execmodule.Executor] = None,
        job_quota: Union[Quota, _MaxQuotaType, None] = None,
        timeout: Optional[timedelta] = None,
        environ: Optional[Dict[str, str]] = None,
        long_running: bool = False,
        stdin: Optional["repomodule.BlobRepository"] = None,
        stdout: Optional["repomodule.BlobRepository"] = None,
        stderr: Optional[Union["repomodule.BlobRepository", _StderrIsStdout]] = None,
        ready: Optional["repomodule.Repository"] = None,
        queries: Optional[Dict[str, pydatatask.query.query.Query]] = None,
        failure_ok: bool = False,
        replicable: bool = False,
        max_replicas: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        """
        :param name: The name of this task.
        :param executor: The executor to use for this task.
        :param job_quota: The amount of resources an individual job should contribute to the quota. Note that this
                              is currently **not enforced** target-side, so jobs may actually take up more resources
                              than assigned.
        :param timeout: The amount of time that a job may take before it is terminated, or None for no timeout.
        :param template: YAML markup for the template of a script to run, either as a string or a path to a file.
        :param environ: Additional environment variables to set on the target machine before running the task.
        :param done: metadata repository in which to dump some information about the process's lifetime and
                     termination on completion. Linked as "done" with
                     ``inhibits_start, required_for_success, is_status``.
        :param stdin: Optional: A blob repository from which to source the process' standard input. The content will be
                      preloaded and transferred to the target environment, so the target does not need to be
                      authenticated to this repository. Linked as "stdin" with ``is_input``.
        :param stdout: Optional: A blob repository into which to dump the process' standard output. The content will be
                       transferred from the target environment on completion, so the target does not need to be
                       authenticated to this repository. Linked as "stdout" with ``is_status``.
        :param stderr: Optional: A blob repository into which to dump the process' standard error, or the constant
                       `pydatatask.task.STDOUT` to indicate that the stream should be interleaved with stdout.
                       Otherwise, the content will be transferred from the target environment on completion, so the
                       target does not need to be authenticated to this repository. Linked as "stderr" with
                       ``is_status``.
        :param ready:  Optional: A repository from which to read task-ready status.
        """
        super().__init__(
            name,
            done,
            ready=ready,
            long_running=long_running,
            timeout=timeout,
            queries=queries,
            failure_ok=failure_ok,
            replicable=replicable,
            max_replicas=max_replicas,
            cache_dir=cache_dir,
        )

        self.template = template
        self.environ = environ or {}
        self.stdin = stdin
        self.stdout = stdout
        self._stderr = stderr
        self._job_quota = job_quota or Quota.parse(1, "1Gi")
        self._executor = executor or execmodule.localhost_manager
        self._manager: Optional[execmodule.AbstractProcessManager] = None
        self.warned = False

        self.link("live", repomodule.LiveProcessRepository(self), None, is_status=True, inhibits_output=True)
        if stdin is not None:
            self.link("stdin", stdin, None, is_input=True)
        if stdout is not None:
            self.link("stdout", stdout, None, is_status=True)
        if isinstance(stderr, repomodule.BlobRepository):
            self.link("stderr", stderr, None, is_status=True)

    def cache_flush(self):
        super().cache_flush()
        if self._executor is not None:
            self._executor.cache_flush()

    @property
    def host(self):
        return self.manager.host

    @property
    def job_quota(self):
        if isinstance(self._job_quota, _MaxQuotaType):
            r = (self._max_quota or self.resource_limit) * self._job_quota
        else:
            r = copy.copy(self._job_quota)
        if r.excess(self.resource_limit):
            r = self.resource_limit * 0.9
            l.warning(
                "%s can never fit within the resource limits. Automatically adjusting its quota to %s",
                self.name,
                r,
            )
            self._job_quota = r
        return r

    @property
    def resource_limit(self):
        return self.manager.quota

    @property
    def manager(self) -> execmodule.AbstractProcessManager:
        """The process manager for this task.

        Will raise an error if the manager comes from a session which is closed.
        """
        if self._manager is None:
            self._manager = self._executor.to_process_manager()
        return self._manager

    @property
    def stderr(self) -> Optional["repomodule.BlobRepository"]:
        """The repository into which stderr will be dumped, or None if it will go to the null device."""
        if isinstance(self._stderr, repomodule.BlobRepository):
            return self._stderr
        else:
            return self.stdout

    @property
    def _unique_stderr(self):
        return self._stderr is not None and not isinstance(self._stderr, _StderrIsStdout)

    async def update(self):
        live, reaped = await self.manager.update(self.name, self.timeout)
        backoff = set()
        for job, replicas in reaped.items():
            success = True
            stdouts: Dict[int, bytes] = {}
            stderrs: Dict[int, bytes] = {}
            dones = {}
            for replica, (stdout, stderr, done) in replicas.items():
                success &= done["success"] | (done["timeout"] and self.long_running)
                if stdout is not None:
                    stdouts[replica] = stdout
                if stderr is not None:
                    stderrs[replica] = stderr
                dones[replica] = done

            if self.stdout is not None:
                async with await self.stdout.open(job, "wb") as fp:
                    if len(stdouts) == 1:
                        (log,) = stdouts.values()
                    else:
                        log = b"".join(f">>> replica {k} <<<\n".encode() + v for k, v in stdouts.items())
                    await fp.write(log)
            if self.stderr is not None and self._unique_stderr:
                async with await self.stderr.open(job, "wb") as fp:
                    if len(stderrs) == 1:
                        (log,) = stderrs.values()
                    else:
                        log = b"".join(f">>> replica {k} <<<\n".encode() + v for k, v in stderrs.items())
                    await fp.write(log)

            if not success and self.require_success and not self.fail_fast:
                l.error(
                    "require_success is set but %s:%s failed. job will be retried.",
                    self.name,
                    job,
                )
                backoff.add(job)
                continue

            if len(dones) == 1:
                (done,) = dones.values()
            else:
                done = {
                    "success": success,
                    "start_time": min(d["start_time"] for d in dones.values()),
                    "end_time": max(d["end_time"] for d in dones.values()),
                    "timeout": all(d["timeout"] for d in dones.values()),
                    "replicas_done": dones,
                }
            await self.done.dump(job, done)

            if not success and self.require_success:
                assert self.fail_fast
                raise Exception(f"require_success is set but {self.name}:{job} failed. fail_fast is set so aborting.")

        return live, set(reaped), backoff

    async def launch(self, job: str, replica: int):
        template_env, preamble, epilogue = await self.build_template_env(job, replica)
        exe_txt = await render_template(self.template, template_env)
        await self._test_auto_values(template_env)
        for item in template_env.values():
            if asyncio.iscoroutine(item):
                item.close()

        exe = self.make_main_script(preamble, exe_txt, epilogue)

        if self._stderr is None:
            stderr: Union[bool, _StderrIsStdout] = False
        elif isinstance(self._stderr, repomodule.BlobRepository):
            stderr = True
        else:
            stderr = self._stderr

        if self.stdin is not None:
            async with await self.stdin.open(job, "rb") as fp:
                await self.manager.launch(
                    self.name, job, replica, exe, self.environ, fp, self.stdout is not None, stderr
                )
        else:
            await self.manager.launch(self.name, job, replica, exe, self.environ, None, self.stdout is not None, stderr)

    async def kill(self, job, replica):
        await self.manager.kill(self.name, job, replica)

    async def killall(self):
        await self.manager.killall(self.name)


class FunctionTaskProtocol(Protocol):
    """The protocol which is expected by the tasks which take a python function to execute."""

    def __call__(self, **kwargs) -> Awaitable[None]: ...


class InProcessSyncTask(Task):
    """A task which runs in-process. Typical usage of this task might look like the following:

    .. code:: python

        @InProcessSyncTask("my_task", done_repo)
        async def my_task(inp, out):
            await out.dump(await inp.info())

        my_task.link("inp", repo_input, LinkKind.InputRepo)
        my_task.link("out", repo_output, LinkKind.OutputRepo)
    """

    def __init__(
        self,
        name: str,
        done: "repomodule.MetadataRepository",
        ready: Optional["repomodule.Repository"] = None,
        func: Optional[FunctionTaskProtocol] = None,
        failure_ok: bool = False,
    ):
        """
        :param name: The name of this task.
        :param done: A metadata repository to store some information about a job's runtime and termination on
                     completion.
        :param ready: Optional: A repository from which to read task-ready status.
        :param func: Optional: The async function to run as the task body, if you don't want to use this task as a
                     decorator.
        """
        super().__init__(name, done, ready=ready, failure_ok=failure_ok)

        self.func = func
        self._env: Dict[str, Any] = {}

    @property
    def job_quota(self):
        return Quota.parse(0, 0)

    @property
    def resource_limit(self):
        return Quota.parse(0, 0)

    @property
    def host(self):
        return LOCAL_HOST

    def __call__(self, f: FunctionTaskProtocol) -> "InProcessSyncTask":
        self.func = f
        return self

    async def validate(self):
        if self.func is None:
            raise ValueError("InProcessSyncTask.func is None")
        await super().validate()

        # sig = inspect.signature(self.func, follow_wrapped=True)
        # for name in sig.parameters.keys():
        #    if name == "job":
        #        self._env[name] = None
        #    elif name in self.links:
        #        self._env[name] = self.links[name].repo
        #    else:
        #        raise NameError("%s takes parameter %s but no such argument is available" % (self.func, name))

    async def update(self):
        return {}, set(), set()

    async def launch(self, job: str, replica: int):
        assert replica == 0
        assert self.func is not None
        start_time = datetime.now(tz=timezone.utc)
        l.info("Launching in-process %s:%s...", self.name, job)
        args, preamble, epilogue = await self.build_template_env(job, replica)
        try:
            for p in preamble:
                p(**args)
            await self.func(**args)
            for e in epilogue:
                e(**args)
        except Exception as e:
            l.info("In-process task %s:%s failed", self.name, job, exc_info=True)
            result: Dict[str, Any] = {
                "success": False,
                "exception": repr(e),
                "traceback": traceback.format_tb(e.__traceback__),
            }
        else:
            l.debug("...success")
            result = {
                "success": True,
                "exception": "",
                "traceback": "",
            }
        result["start_time"] = start_time
        result["end_time"] = datetime.now(tz=timezone.utc)
        result["timeout"] = False
        if self.metadata:
            await self.done.dump(job, result)

    async def kill(self, job, replica):
        return

    async def killall(self):
        return


class ExecutorTask(Task):
    """A task which runs python functions in a :external:class:`concurrent.futures.Executor`. This has not been
    tested on anything but the :external:class:`concurrent.futures.ThreadPoolExecutor`, so beware!

    See `InProcessSyncTask` for information on how to use instances of this class as decorators for their bodies.

    It is expected that the executor will perform all necessary resource quota management.
    """

    def __init__(
        self,
        name: str,
        executor: FuturesExecutor,
        job_quota: Union[Quota, _MaxQuotaType],
        resource_limit: Quota,
        done: "repomodule.MetadataRepository",
        host: Optional[Host] = None,
        long_running: bool = False,
        ready: Optional["repomodule.Repository"] = None,
        failure_ok: bool = False,
        func: Optional[Callable] = None,
    ):
        """
        :param name: The name of this task.
        :param executor: The executor to run jobs in.
        :param done: A metadata repository to store some information about a job's runtime and termination on
                     completion.
        :param ready: Optional: A repository from which to read task-ready status.
        :param func: Optional: The async function to run as the task body, if you don't want to use this task as a
                     decorator.
        """
        super().__init__(name, done, ready, long_running=long_running, failure_ok=failure_ok)

        if host is None:
            if isinstance(executor, ThreadPoolExecutor):
                host = LOCAL_HOST
            else:
                raise ValueError(
                    "Can't figure out what host this task runs on automatically - "
                    "please provide ExecutorTask with the host parameter"
                )

        self.executor = executor
        self._host = host
        self.func = func
        self.jobs: Dict[ConcurrentFuture[datetime], Tuple[str, datetime]] = {}
        self.rev_jobs: Dict[str, ConcurrentFuture[datetime]] = {}
        self.live = repomodule.ExecutorLiveRepo(self)
        self._env: Dict[str, Any] = {}
        self._job_quota = job_quota
        self._resource_limit = resource_limit
        self.link("live", self.live, None, is_status=True, inhibits_output=True, inhibits_start=True)

    def __call__(self, f: Callable) -> "ExecutorTask":
        self.func = f
        return self

    @property
    def job_quota(self):
        if isinstance(self._job_quota, _MaxQuotaType):
            r = (self._max_quota or self.resource_limit) * self._job_quota
        else:
            r = copy.copy(self._job_quota)
        if r.excess(self.resource_limit):
            r = self.resource_limit * 0.9
            l.warning(
                "%s can never fit within the resource limits. Automatically adjusting its quota to %s",
                self.name,
                r,
            )
            self._job_quota = r
        return r

    @property
    def resource_limit(self):
        return self._resource_limit

    @property
    def host(self):
        return self._host

    async def kill(self, job: str, replica: int):
        assert replica == 0
        self.rev_jobs[job].cancel()

    async def killall(self):
        for job in self.jobs:
            job.cancel()

    async def update(self):
        done, _ = wait(self.jobs, 0, FIRST_EXCEPTION)
        coros = []
        dead: Set[str] = set()
        live = set(self.rev_jobs)
        for finished_job in done:
            job, start_time = self.jobs.pop(finished_job)
            self.rev_jobs.pop(job)
            coros.append(self._cleanup(finished_job, job, start_time))
            dead.add(job)
        await asyncio.gather(*coros)
        live -= dead
        return {(job, cast(int, 0)): self.jobs[self.rev_jobs[job]][1] for job in live}, dead, set()

    async def _cleanup(self, job_future, job, start_time):
        e = job_future.exception()
        if e is not None:
            l.info("Executor task %s:%s failed", self.name, job, exc_info=e)
            data = {
                "success": False,
                "exception": repr(e),
                "traceback": traceback.format_tb(e.__traceback__),
                "end_time": datetime.now(tz=timezone.utc),
            }
        else:
            l.debug("...executor task %s:%s success", self.name, job)
            data = {
                "success": True,
                "end_time": job_future.result(),
                "exception": "",
                "traceback": "",
            }
        data["start_time"] = start_time
        data["timeout"] = False
        await self.done.dump(job, data)

    async def validate(self):
        if self.func is None:
            raise ValueError("InProcessAsyncTask %s has func None" % self.name)

        sig = inspect.signature(self.func, follow_wrapped=True)
        for name, param in sig.parameters.items():
            if param.kind == param.VAR_KEYWORD:
                pass
            elif name in self.links:
                self._env[name] = self.links[name].repo
            else:
                raise NameError("%s takes parameter %s but no such argument is available" % (self.func, name))

        await super().validate()

    async def launch(self, job, replica):
        assert replica == 0
        l.info("Launching %s:%s with %s...", self.name, job, self.executor)
        args, preamble, epilogue = await self.build_template_env(job, replica)
        start_time = datetime.now(tz=timezone.utc)
        running_job = self.executor.submit(self._timestamped_func, self.func, preamble, args, epilogue)
        if self.synchronous:
            while not running_job.done():
                await asyncio.sleep(0.1)
            await self._cleanup(running_job, job, start_time)
        else:
            self.jobs[running_job] = (job, start_time)
            self.rev_jobs[job] = running_job

    async def cancel(self, job):
        """Stop the current job from running, or do nothing if it is not running."""
        future = self.rev_jobs.pop(job)
        if future is not None:
            future.cancel()
            self.jobs.pop(future)

    @staticmethod
    def _timestamped_func(func, preamble, args, epilogue) -> datetime:
        loop = asyncio.new_event_loop()
        for p in preamble:
            loop.run_until_complete(p(**args))
        loop.run_until_complete(func(**args))
        for p in epilogue:
            loop.run_until_complete(p(**args))
        return datetime.now(tz=timezone.utc)


class KubeFunctionTask(KubeTask):
    """A task which runs a python function on a kubernetes cluster. Requires a pod template which will execute a.

    python script calling `pydatatask.main.main`. This works by running ``python3 main.py launch [task] [job]
    --sync``.

    Sample usage:

    .. code:: python

        @KubeFunctionTask(
            "my_task",
            podman,
            resman,
            '''
                apiVersion: v1
                kind: Pod
                spec:
                  containers:
                    - name: leader
                      image: "docker.example.com/my/image"
                      command:
                        - python3
                        - {{argv0}}
                        - launch
                        - "{{task}}"
                        - "{{job}}"
                        - "--force"
                        - "--sync"
                      resources:
                        requests:
                          cpu: 100m
                          memory: 1Gi
            ''',
            repo_done,
            repo_func_done,
            repo_logs,
        )
        async def my_task(inp, out):
            await out.dump(await inp.info())

        my_task.link("inp", repo_input, LinkKind.InputRepo)
        my_task.link("out", repo_output, LinkKind.OutputRepo)
    """

    def __init__(
        self,
        name: str,
        executor: "execmodule.Executor",
        template: Union[str, Path],
        kube_done: "repomodule.MetadataRepository",
        func_done: "repomodule.MetadataRepository",
        logs: Optional["repomodule.BlobRepository"] = None,
        template_env: Optional[Dict[str, Any]] = None,
        failure_ok: bool = False,
        func: Optional[Callable] = None,
    ):
        """
        :param name: The name of this task.
        :param executor: The executor to use for this task.
        :param template: YAML markup for a pod manifest template that will run `pydatatask.main.main` as
                         ``python3 main.py launch [task] [job] --sync --force``, either as a string or a path to a file.
        :param logs: Optional: A BlobRepository to dump pod logs to on completion. Linked as "logs" with
                               ``is_status``.
        :param kube_done: A MetadataRepository in which to dump some information about the pod's lifetime and
                          termination on completion. Linked as "done" with
                          ``inhibits_start, required_for_success, is_status``.
        :param func_done: Optional: A MetadataRepository in which to dump some information about the function's lifetime
                          and termination on completion. Linked as "func_done" with
                          ``inhibits_start, required_for_success, is_status``.
        :param template_env:     Optional: Additional keys to add to the template environment.
        :param ready:   Optional: A repository from which to read task-ready status.
        :param func: Optional: The async function to run as the task body, if you don't want to use this task as a
                     decorator.
        """
        super().__init__(name, executor, template, logs, kube_done, template_env=template_env, failure_ok=failure_ok)
        self.func = func
        self.func_done = func_done
        if func_done is not None:
            self.link(
                "func_done",
                func_done,
                None,
                required_for_success=True,
                is_status=True,
                inhibits_start=True,
            )
        self._func_env: Dict[str, Any] = {}

    def __call__(self, f: Callable) -> "KubeFunctionTask":
        self.func = f
        return self

    async def validate(self):
        if self.func is None:
            raise ValueError("KubeFunctionTask %s has func None" % self.name)

        sig = inspect.signature(self.func, follow_wrapped=True)
        for name in sig.parameters.keys():
            if name in self.links:
                self._func_env[name] = self.links[name].repo
            else:
                raise NameError("%s takes parameter %s but no such argument is available" % (self.func, name))

        await super().validate()

    async def launch(self, job: str, replica):
        assert replica == 0
        if self.synchronous:
            await self._launch_sync(job)
        else:
            await super().launch(job, replica)

    async def _launch_sync(self, job: str):
        assert self.func is not None
        start_time = datetime.now(tz=timezone.utc)
        l.info("Launching --sync %s:%s...", self.name, job)
        args, preamble, epilogue = await self.build_template_env(job, 0)
        try:
            for p in preamble:
                await p(**args)
            await self.func(**args)
            for p in epilogue:
                await p(**args)
        except Exception as e:
            l.info("--sync task %s:%s failed", self.name, job, exc_info=True)
            result: Dict[str, Any] = {
                "success": False,
                "exception": repr(e),
                "traceback": traceback.format_tb(e.__traceback__),
            }
        else:
            l.debug("...success")
            result = {
                "success": True,
                "exception": "",
                "traceback": "",
            }
        result["start_time"] = start_time
        result["end_time"] = datetime.now(tz=timezone.utc)
        result["timeout"] = False
        if self.metadata and self.func_done is not None:
            await self.func_done.dump(job, result)


class ContainerTask(TemplateShellTask):
    """A task that runs a container."""

    def __init__(
        self,
        name: str,
        image: str,
        template: str,
        done: "repomodule.MetadataRepository",
        executor: execmodule.Executor,
        entrypoint: Iterable[str] = ("/bin/sh", "-c"),
        job_quota: Union[Quota, _MaxQuotaType, None] = None,
        fallback_quota: Union[Quota, _MaxQuotaType, None] = None,
        timeout: Optional[timedelta] = None,
        environ: Optional[Dict[str, str]] = None,
        mounts: Optional[Dict[str, str]] = None,
        long_running: bool = False,
        logs: Optional["repomodule.BlobRepository"] = None,
        ready: Optional["repomodule.Repository"] = None,
        privileged: Optional[bool] = False,
        tty: Optional[bool] = False,
        queries: Optional[Dict[str, pydatatask.query.query.Query]] = None,
        failure_ok: bool = False,
        replicable: bool = False,
        max_replicas: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        """
        :param name: The name of this task.
        :param image: The name of the docker image to use to run this task. Can be a jinja template.
        :param executor: The executor to use for this task.
        :param job_quota: The amount of resources an individual job should contribute to the quota. Note that this
                              is currently **not enforced** target-side, so jobs may actually take up more resources
                              than assigned.
        :param template: YAML markup for the template of a script to run, either as a string or a path to a file.
        :param environ: Additional environment variables to set on the target container before running the task.
        :param timeout: How long a task can take before it is killed for taking too long, or None for no timeout.
        :param done: Optional: A metadata repository in which to dump some information about the container's lifetime
                               and termination on completion. Linked as "done" with
                               ``inhibits_start, required_for_success, is_status``.
        :param logs: Optional: A blob repository into which to dump the container's logs. Linked as "logs" with
                               ``is_status``.
        :param ready:  Optional: A repository from which to read task-ready status.
        """
        super().__init__(
            name,
            done,
            ready=ready,
            long_running=long_running,
            timeout=timeout,
            queries=queries,
            failure_ok=failure_ok,
            replicable=replicable,
            max_replicas=max_replicas,
            cache_dir=cache_dir,
        )

        self.template = template
        self.entrypoint = entrypoint
        self.image = image
        self.environ = environ or {}
        self.logs = logs
        self._job_quota = job_quota or Quota.parse(1, "1Gi")
        self._fallback_quota = fallback_quota
        self._executor = executor
        self._manager: Optional[execmodule.AbstractContainerManager] = None
        self.warned = False
        self.privileged = privileged
        self.tty = tty
        self.mounts: Dict[str, str] = mounts or {}

        if logs is not None:
            self.link("logs", logs, None, is_status=True)
        self.link(
            "live",
            repomodule.LiveContainerRepository(self),
            None,
            is_status=True,
            inhibits_output=True,
        )

    def cache_flush(self):
        super().cache_flush()
        if self._executor is not None:
            self._executor.cache_flush()

    @property
    def host(self):
        return self.manager.host

    @property
    def job_quota(self):
        if isinstance(self._job_quota, _MaxQuotaType):
            r = (self._max_quota or self.resource_limit) * self._job_quota
        else:
            r = copy.copy(self._job_quota)
        if r.excess(self.resource_limit):
            r = self.resource_limit * 0.9
            l.warning(
                "%s can never fit within the resource limits. Automatically adjusting its quota to %s",
                self.name,
                r,
            )
            self._job_quota = r
        return r

    @property
    def fallback_quota(self):
        if self._fallback_quota is None:
            return None
        if isinstance(self._fallback_quota, _MaxQuotaType):
            r = (self._max_quota or self.resource_limit) * self._fallback_quota
        else:
            r = copy.copy(self._fallback_quota)
        if r.excess(self.resource_limit):
            r = self.resource_limit * 0.9
            l.warning(
                "%s can never fit within the resource limits. Automatically adjusting its quota to %s",
                self.name,
                r,
            )
            self._fallback_quota = r
        return r

    @property
    def resource_limit(self):
        return self.manager.quota

    @property
    def manager(self) -> execmodule.AbstractContainerManager:
        """The process manager for this task.

        Will raise an error if the manager comes from a session which is closed.
        """
        if self._manager is None:
            self._manager = self._executor.to_container_manager()
        return self._manager

    async def update(self):
        live, reaped = await self.manager.update(self.name, timeout=self.timeout)
        backoff = set()
        for job, replicas in reaped.items():
            success = True
            logs = {}
            dones = {}
            for replica, (log, done) in replicas.items():
                success &= done["success"] | (done["timeout"] and self.long_running)
                logs[replica] = log
                dones[replica] = done

            if self.logs is not None:
                async with await self.logs.open(job, "wb") as fp:
                    if len(logs) == 1:
                        (log,) = logs.values()
                    else:
                        log = b"".join(f">>> replica {k} <<<\n".encode() + v for k, v in logs.items() if v is not None)
                    if log:
                        await fp.write(log)

            if not success and self.require_success and not self.fail_fast:
                l.error(
                    "require_success is set but %s:%s failed. job will be retried.",
                    self.name,
                    job,
                )
                backoff.add(job)
                continue

            if len(dones) == 1:
                (done,) = dones.values()
            else:
                done = {
                    "success": success,
                    "start_time": min(d["start_time"] for d in dones.values()),
                    "end_time": max(d["end_time"] for d in dones.values()),
                    "timeout": all(d["timeout"] for d in dones.values()),
                    "replicas_done": dones,
                }
            await self.done.dump(job, done)

            if not success and self.require_success:
                assert self.fail_fast
                raise Exception(f"require_success is set but {self.name}:{job} failed. fail_fast is set so aborting.")

        return live, set(reaped), backoff

    async def launch(self, job: str, replica: int):
        template_env, preamble, epilogue = await self.build_template_env(job, replica)
        exe_txt = await render_template(self.template, template_env)
        image = await render_template(self.image, template_env)
        await self._test_auto_values(template_env)
        exe_txt = self.make_main_script(preamble, exe_txt, epilogue)
        for item in template_env.values():
            if asyncio.iscoroutine(item):
                item.close()

        privileged = bool(self.privileged)
        tty = bool(self.tty)
        await self.manager.launch(
            self.name,
            job,
            replica,
            image,
            list(self.entrypoint),
            exe_txt,
            self.environ,
            self.job_quota,
            self.mounts,
            privileged,
            tty,
        )

    async def kill(self, job, replica):
        await self.manager.kill(self.name, job, replica)

    async def killall(self):
        await self.manager.killall(self.name)


class ContainerSetTask(TemplateShellTask):
    """THE FIREY BELL TOLLS ITS DARK TOLL."""

    def __init__(
        self,
        name: str,
        image: str,
        template: str,
        done: "repomodule.MetadataRepository",
        executor: execmodule.Executor,
        entrypoint: Iterable[str] = ("/bin/sh", "-c"),
        job_quota: Union[Quota, _MaxQuotaType, None] = None,
        timeout: Optional[timedelta] = None,
        environ: Optional[Dict[str, str]] = None,
        mounts: Optional[Dict[str, str]] = None,
        long_running: bool = False,
        logs: Optional["repomodule.BlobRepository"] = None,
        ready: Optional["repomodule.Repository"] = None,
        privileged: Optional[bool] = False,
        tty: Optional[bool] = False,
        queries: Optional[Dict[str, pydatatask.query.query.Query]] = None,
        failure_ok: bool = False,
        replicable: bool = False,
        max_replicas: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        super().__init__(
            name,
            done,
            ready=ready,
            long_running=long_running,
            timeout=timeout,
            queries=queries,
            failure_ok=failure_ok,
            replicable=replicable,
            max_replicas=max_replicas,
            cache_dir=cache_dir,
        )

        if not long_running:
            raise Exception("ContainerSetTask MUST be long running")
        self.template = template
        self.entrypoint = entrypoint
        self.image = image
        self.environ = environ or {}
        self.logs = logs
        self._job_quota = job_quota or Quota.parse(1, "1Gi")
        self._executor = executor
        self._manager: Optional[execmodule.AbstractContainerSetManager] = None
        self.warned = False
        self.privileged = privileged
        self.tty = tty
        self.mounts: Dict[str, str] = mounts or {}
        self._node_count = None

        if logs is not None:
            self.link("logs", logs, None, is_status=True)
        self.link(
            "live",
            repomodule.LiveContainerSetRepository(self),
            None,
            is_status=True,
            inhibits_output=True,
        )

    async def validate(self):
        self._node_count = await self.manager.size()

    @property
    def node_count(self):
        if self._node_count is None:
            raise Exception("Pipeline is not open")
        return self._node_count

    def cache_flush(self):
        super().cache_flush()
        if self._executor is not None:
            self._executor.cache_flush()

    @property
    def host(self):
        return self.manager.host

    @property
    def job_quota(self):
        if isinstance(self._job_quota, _MaxQuotaType):
            r = (self._max_quota or self.resource_limit) * self._job_quota
        else:
            r = copy.copy(self._job_quota)
        if (r * self.node_count).excess(self.resource_limit):
            r = self.resource_limit * (0.9 / self.node_count)
            l.warning(
                "%s can never fit within the resource limits. Automatically adjusting its quota to %s",
                self.name,
                r,
            )
            self._job_quota = r
        return r * self.node_count

    @property
    def resource_limit(self):
        return self.manager.quota

    @property
    def manager(self) -> execmodule.AbstractContainerSetManager:
        """The process manager for this task.

        Will raise an error if the manager comes from a session which is closed.
        """
        if self._manager is None:
            self._manager = self._executor.to_container_set_manager()
        return self._manager

    async def update(self):
        live, reaped = await self.manager.update(self.name, timeout=self.timeout)
        backoff = set()
        for job, replicas in reaped.items():
            success = True
            logs = {}
            dones = {}
            for replica, (log, done) in replicas.items():
                success &= done["success"] | (done["timeout"] and self.long_running)
                logs[replica] = log
                dones[replica] = done

            if self.logs is not None:
                async with await self.logs.open(job, "wb") as fp:
                    if len(logs) == 1:
                        (log,) = logs.values()
                    else:
                        log = b"".join(f">>> replica {k} <<<\n".encode() + v for k, v in logs.items() if v is not None)
                    if log:
                        await fp.write(log)

            if not success and self.require_success and not self.fail_fast:
                l.error(
                    "require_success is set but %s:%s failed. job will be retried.",
                    self.name,
                    job,
                )
                backoff.add(job)
                continue

            if len(dones) == 1:
                (done,) = dones.values()
            else:
                done = {
                    "success": success,
                    "start_time": min(d["start_time"] for d in dones.values()),
                    "end_time": max(d["end_time"] for d in dones.values()),
                    "timeout": all(d["timeout"] for d in dones.values()),
                    "replicas_done": dones,
                }
            await self.done.dump(job, done)

            if not success and self.require_success:
                assert self.fail_fast
                raise Exception(f"require_success is set but {self.name}:{job} failed. fail_fast is set so aborting.")

        return live, set(reaped), backoff

    async def launch(self, job: str, replica: int):
        template_env, preamble, epilogue = await self.build_template_env(job, replica)
        exe_txt = await render_template(self.template, template_env)
        image = await render_template(self.image, template_env)
        await self._test_auto_values(template_env)
        exe_txt = self.make_main_script(preamble, exe_txt, epilogue)
        for item in template_env.values():
            if asyncio.iscoroutine(item):
                item.close()

        privileged = bool(self.privileged)
        tty = bool(self.tty)
        await self.manager.launch(
            self.name,
            job,
            replica,
            image,
            list(self.entrypoint),
            exe_txt,
            self.environ,
            self.job_quota * (1 / self.node_count),
            self.mounts,
            privileged,
            tty,
        )

    async def kill(self, job, replica):
        await self.manager.kill(self.name, job, replica)

    async def killall(self):
        await self.manager.killall(self.name)
