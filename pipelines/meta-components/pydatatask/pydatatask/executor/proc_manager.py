"""A process manager can be used with a ProcessTask to specify where and how the processes should run.

All a process manager needs to specify is how to launch a process and manipulate the filesystem, and the ProcessTask
will set up an appropriate environment for running the task and retrieve the results using this interface.
"""

from typing import (
    TYPE_CHECKING,
    Any,
    AsyncContextManager,
    DefaultDict,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
    overload,
)
from abc import abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import asyncio
import getpass
import os
import shlex
import signal
import subprocess
import sys

from aiohttp import web
import aiofiles.os
import aioshutil
import asyncssh
import psutil
import yaml

from pydatatask import agent
from pydatatask.executor import Executor
from pydatatask.executor.container_manager import (
    AbstractContainerManager,
    DockerContainerManager,
    KubeContainerManager,
    docker_connect,
)
from pydatatask.executor.container_set_manager import (
    DockerContainerSetManager,
    KubeContainerSetManager,
)
from pydatatask.executor.pod_manager import PodManager, VolumeSpec, kube_connect
from pydatatask.host import LOCAL_HOST, Host, HostOS
from pydatatask.quota import LOCALHOST_QUOTA, Quota
from pydatatask.session import Ephemeral, SessionOpenFailedError

from ..utils import (
    AReadStream,
    AReadStreamBase,
    AReadTextProto,
    AWriteStream,
    AWriteTextProto,
    _StderrIsStdout,
    async_copyfile,
    safe_load,
)

if TYPE_CHECKING:
    from ..utils import AReadStreamManager, AReadText, AWriteStreamManager, AWriteText

__all__ = (
    "AbstractProcessManager",
    "LocalLinuxManager",
    "SSHLinuxManager",
    "InProcessLocalLinuxManager",
    "LocalLinuxOrKubeManager",
)


class AbstractProcessManager(Executor):
    """The base class for process managers.

    Processes are managed through arbitrary "process identifier" handle strings.
    """

    def __init__(self, quota: Quota, tmp_path: Union[str, Path]):
        super().__init__(quota)
        self._tmp_path = Path(tmp_path)

    def to_process_manager(self) -> "AbstractProcessManager":
        return self

    @abstractmethod
    async def _get_live_pids(self, hint: Set[str]) -> Set[str]:
        """Get a set of the live process identifiers.

        This must return a subset of hint.
        """
        raise NotImplementedError

    async def launch(
        self,
        task: str,
        job: str,
        replica: int,
        script: str,
        environ: Dict[str, str],
        stdin: Union[AReadStreamBase, None],
        stdout: bool,
        stderr: Union[bool, "_StderrIsStdout"],
    ):
        """Launch!

        That! Job!
        """
        basedir = self._basedir / task / job / str(replica)
        dirmade = False
        pid = None
        try:
            cwd_path = basedir / "cwd"
            stdout_path = basedir / "stdout" if stdout else None
            if stderr is True:
                stderr_path: Union[_StderrIsStdout, Path, None] = basedir / "stderr"
            elif stderr is False:
                stderr_path = None
            else:
                stderr_path = stderr
            return_code = basedir / "return_code"
            info_path = basedir / "info"
            script_path = basedir / "exe"
            await self._mkdir(cwd_path)
            dirmade = True
            async with await self._open(script_path, "w") as fp:
                await fp.write(script)
            await self._chmod(script_path, 0o755)
            if stdin is not None:
                stdin_path = basedir / "stdin"
                async with await self._open(stdin_path, "wb") as fp:
                    await async_copyfile(stdin, fp)
            else:
                stdin_path = None
            pid = await self._spawn(
                ["/bin/sh", "-c", str(script_path)],
                environ,
                cwd_path,
                return_code,
                stdin_path,
                stdout_path,
                stderr_path,
            )
            async with await self._open(info_path, "w") as fp:
                await fp.write(yaml.safe_dump({"pid": pid, "start_time": datetime.now(tz=timezone.utc)}))
        except:
            try:
                if dirmade:
                    await self._rmtree(basedir)
            except:  # pylint: disable=bare-except
                pass
            try:
                if pid is not None:
                    await self._kill(pid)
            except:  # pylint: disable=bare-except
                pass
            raise

    @abstractmethod
    async def _spawn(
        self,
        args: List[str],
        environ: Dict[str, str],
        cwd: Union[str, Path],
        return_code: Union[str, Path],
        stdin: Union[str, Path, None],
        stdout: Union[str, Path, None],
        stderr: Union[str, Path, "_StderrIsStdout", None],
    ) -> str:
        """Launch a process on the target system. This function MUST NOT wait until the process has terminated
        before returning.

        :param args: The command line of the process to launch. ``args[0]`` is the executable to run.
        :param environ: A set of environment variables to add to the target process' environment.
        :param cwd: The directory to launch the process in.
        :param return_code: A filepath in which to store the process exit code, as an ascii integer.
        :param stdin: A filepath from which to read the process' stdin, or None for a null file.
        :param stdout: A filepath to which to write the process' stdout, or None for a null file.
        :param stderr: A filepath to which to write the process' stderr, None for a null file, or the constant
            `pydatatask.task.STDOUT` to interleave it into the stdout stream.
        :return: The process identifier of the process spawned.
        """
        raise NotImplementedError

    async def kill(self, task: str, job: str, replica: int):
        """Terminate the process with the given identifier.

        This should do nothing if the process is not currently running.
        """
        basedir = self._basedir / task / job / str(replica)
        info_path = basedir / "info"
        async with await self._open(info_path, "rb") as fp:
            info = safe_load(await fp.read())
        pid = info["pid"]
        await self._kill(pid)
        await asyncio.sleep(0.1)  # don't race with return_code writing
        await self._rmtree(basedir)

    async def killall(self, task: str):
        """Terminate all processes for the given task."""
        task_dir = self._basedir / task

        async def job_guy(job: str):
            replicas = await self._readdir(task_dir / job)
            return await asyncio.gather(*(self.kill(task, job, int(x)) for x in replicas))

        jobs = await self._readdir(task_dir)
        await asyncio.gather(*(job_guy(job) for job in jobs))

    @abstractmethod
    async def _kill(self, pid: str):
        raise NotImplementedError

    async def update(
        self, task: str, timeout: Optional[timedelta] = None
    ) -> Tuple[
        Dict[Tuple[str, int], datetime], Dict[str, Dict[int, Tuple[Optional[bytes], Optional[bytes], Dict[str, Any]]]]
    ]:
        """Perform routine maintenence on the running set of jobs for the given task.

        Should return a tuple of a bool indicating whether any jobs were running before this function was called, and a
        dict mapping finished job names to a tuple of the output logs from the job and a dict with any metadata left
        over from any replicas of the job.

        If any job has been alive for longer than timeout, kill it and return it as part of the finished jobs.
        """
        task_dir = self._basedir / task
        jobs = await self._readdir(task_dir)

        async def replica_guy(job: str, replica: int):
            async with await self._open(task_dir / job / str(replica) / "info", "rb") as fp:
                return (job, replica, safe_load(await fp.read()))

        async def job_guy(job: str):
            replicas = await self._readdir(task_dir / job)
            return await asyncio.gather(*(replica_guy(job, int(x)) for x in replicas))

        infos = [
            (job, replica, info)
            for replicas in await asyncio.gather(*(job_guy(job) for job in jobs))
            for (job, replica, info) in replicas
        ]
        info_by_pids = {info["pid"]: (job, replica, info) for job, replica, info in infos}
        maybe_pids = set(info_by_pids)
        live_pids = await self._get_live_pids(maybe_pids)
        dead_pids = maybe_pids - live_pids
        now = datetime.now(tz=timezone.utc)
        if timeout is not None:
            timeout_pids = {pid for pid in live_pids if info_by_pids[pid][2]["start_time"] + timeout > now}
        else:
            timeout_pids = set()

        await asyncio.gather(*(self._kill(pid) for pid in timeout_pids))
        for pid in timeout_pids:
            info_by_pids[pid][2]["timeout"] = True
        for pid in dead_pids:
            info_by_pids[pid][2]["timeout"] = False
        live_pids -= timeout_pids
        dead_pids |= timeout_pids
        live_replicas = {
            (job, replica): info["start_time"] for pid, (job, replica, info) in info_by_pids.items() if pid in live_pids
        }
        live_jobs = {job for job, _ in live_replicas}

        async def io_guy(
            job: str, replica: int, info: Dict[str, Any]
        ) -> Tuple[str, int, Dict[str, Any], Optional[bytes], Optional[bytes]]:
            rep_dir = task_dir / job / str(replica)
            try:
                async with await self._open(rep_dir / "stdout", "rb") as fp:
                    stdout = await fp.read()
            except FileNotFoundError:
                stdout = None
            try:
                async with await self._open(rep_dir / "stderr", "rb") as fp:
                    stderr = await fp.read()
            except FileNotFoundError:
                stderr = None
            try:
                async with await self._open(rep_dir / "return_code", "r") as fp:
                    info["exit_code"] = int(await fp.read())
            except FileNotFoundError:
                info["exit_code"] = 1
            await self._rmtree(rep_dir)
            return job, replica, info, stdout, stderr

        io_results = await asyncio.gather(*(io_guy(*info_by_pids[pid]) for pid in dead_pids))
        final: DefaultDict[str, Dict[int, Tuple[Optional[bytes], Optional[bytes], Dict[str, Any]]]] = defaultdict(dict)
        for job, replica, info, stdout, stderr in io_results:
            info["success"] = info["exit_code"] == 0
            info["end_time"] = now
            if job not in live_jobs:
                final[job][replica] = (stdout, stderr, info)

        return live_replicas, final

    async def live(self, task: str, job: Optional[str] = None) -> Dict[Tuple[str, int], datetime]:
        """We!

        Are! Live!
        """
        task_dir = self._basedir / task
        if job is not None:
            jobs = [job]
        else:
            jobs = await self._readdir(task_dir)

        async def replica_guy(job: str, replica: int):
            async with await self._open(task_dir / job / str(replica) / "info", "rb") as fp:
                return (job, replica, safe_load(await fp.read()))

        async def job_guy(job: str):
            replicas = await self._readdir(task_dir / job)
            return await asyncio.gather(*(replica_guy(job, int(x)) for x in replicas))

        infos = [
            (job, replica, info)
            for replicas in await asyncio.gather(*(job_guy(job) for job in jobs))
            for (job, replica, info) in replicas
        ]
        return {(job, replica): info["start_time"] for job, replica, info in infos}

    @property
    @abstractmethod
    def _basedir(self) -> Path:
        """A path on the target system to a directory which can be freely manipulated by the app."""
        raise NotImplementedError

    @overload
    @abstractmethod
    async def _open(self, path: Union[Path, str], mode: Literal["r"]) -> AsyncContextManager["AReadTextProto"]: ...

    @overload
    @abstractmethod
    async def _open(self, path: Union[Path, str], mode: Literal["w"]) -> AsyncContextManager["AWriteTextProto"]: ...

    @overload
    @abstractmethod
    async def _open(self, path: Union[Path, str], mode: Literal["rb"]) -> AsyncContextManager["AReadStream"]: ...

    @overload
    @abstractmethod
    async def _open(self, path: Union[Path, str], mode: Literal["wb"]) -> AsyncContextManager["AWriteStream"]: ...

    @abstractmethod
    async def _open(self, path, mode):
        """Open the file on the target system for reading or writing according to the given mode."""
        raise NotImplementedError

    @abstractmethod
    async def _chmod(self, path: Union[Path, str], mode: int):
        """Change the mode of the given file on the target system."""
        raise NotImplementedError

    @abstractmethod
    async def _mkdir(self, path: Path):  # exist_ok=True, parents=True
        """Create a directory with the given path on the target system.

        This should have the semantics of ``mkdir -p``, i.e. create any necessary parent directories and also succeed if
        the directory already exists.
        """
        raise NotImplementedError

    @abstractmethod
    async def _rmtree(self, path: Path):
        """Remove a directory and all its children with the given path on the target system."""
        raise NotImplementedError

    @abstractmethod
    async def _readdir(self, path: Path) -> List[str]:
        """Return the contents of the given directory.

        Returns just the basenames.
        """
        raise NotImplementedError


class LocalLinuxManager(AbstractProcessManager):
    """A process manager to run tasks on the local linux machine.

    By default, it will create a directory ``/tmp/pydatatask-{getpass.getuser()}`` in which to store data.
    """

    def to_container_manager(self) -> AbstractContainerManager:
        if self._local_docker is not None:
            dir(self._local_docker.docker)
            return self._local_docker
        raise TypeError("Not configured to connect to docker (pass nil_ephemeral, lol)")

    def to_container_set_manager(self):
        if self._local_docker_set is not None:
            dir(self._local_docker_set._docker_manager.docker)
            return self._local_docker_set
        raise TypeError("Not configured to connect to docker (pass nil_ephemeral, lol)")

    def cache_flush(self):
        super().cache_flush()
        if self._local_docker is not None:
            self._local_docker.cache_flush()
        if self._local_docker_set is not None:
            self._local_docker_set.cache_flush()

    def __init__(
        self,
        *,
        quota: Quota = LOCALHOST_QUOTA,
        app: str,
        local_path: Union[Path, str] = f"{os.environ.get('TEMP', '/tmp')}/pydatatask-{getpass.getuser()}",
        image_prefix: str = "",
        nil_ephemeral: Optional[Ephemeral[None]] = None,
        host_path_overrides: Optional[Dict[str, str]] = None,
    ):
        super().__init__(quota, Path(local_path) / app)
        self.app = app
        self._image_prefix = image_prefix
        if nil_ephemeral is not None:
            # This MIGHT not work on machines without docker installed.
            self._local_docker: Optional[DockerContainerManager] = DockerContainerManager(
                quota=quota,
                app=app,
                docker=nil_ephemeral._session.ephemeral(docker_connect(), optional=True, name=f"{app}_local_docker"),
                image_prefix=image_prefix,
                host_path_overrides=host_path_overrides,
            )
            self._local_docker_set: Optional[DockerContainerSetManager] = DockerContainerSetManager(
                quota=quota,
                app=app,
                docker=nil_ephemeral._session.ephemeral(docker_connect(), optional=True, name=f"{app}_local_docker"),
                image_prefix=image_prefix,
                host_path_overrides=host_path_overrides,
            )
        else:
            self._local_docker = None
            self._local_docker_set = None

    @property
    def host(self) -> Host:
        return LOCAL_HOST

    @property
    def _basedir(self) -> Path:
        return self._tmp_path

    async def _get_live_pids(self, hint: Set[str]) -> Set[str]:
        return {str(x) for x in psutil.pids()} & hint

    async def _readdir(self, path):
        try:
            return await aiofiles.os.listdir(path)
        except FileNotFoundError:
            return []

    async def _spawn(self, args, environ, cwd, return_code, stdin, stdout, stderr):
        if stdin is None:
            stdin_real = "/dev/null"
        else:
            stdin_real = shlex.quote(str(stdin))
        if stdout is None:
            stdout_real = "/dev/null"
        else:
            stdout_real = shlex.quote(str(stdout))
        if stderr is None:
            stderr_real = "/dev/null"
        elif isinstance(stderr, _StderrIsStdout):
            stderr_real = "&1"
        else:
            stderr_real = shlex.quote(str(stderr))
        return_code = shlex.quote(str(return_code))
        cmd = f"""
        {shlex.join(args)} <{stdin_real} >{stdout_real} 2>{stderr_real} &
        PID=$!
        echo $PID
        wait $PID >/dev/null 2>/dev/null
        echo $? >{return_code} 2>/dev/null
        """
        p = subprocess.Popen(  # pylint: disable=consider-using-with
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            close_fds=True,
            cwd=cwd,
            env=environ,
        )
        assert p.stdout is not None
        pid = p.stdout.readline()
        return pid.decode().strip()

    async def _kill(self, pid: str):
        try:
            os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    async def _chmod(self, path, mode):
        os.chmod(path, mode)

    async def _mkdir(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)

    async def _rmtree(self, path: Path):
        await aioshutil.rmtree(path)

    async def _open(self, path, mode):
        return aiofiles.open(path, mode)

    async def _agent_live(self) -> Tuple[Optional[str], Optional[str]]:
        """Determine whether the agent is alive.

        If so, return (pid, version_string). Otherwise, return (None, None)
        """
        agent_path = self._basedir / "agent"
        try:
            async with await self._open(agent_path, "r") as fp:
                bdata = await fp.read()
            data = safe_load(bdata)
            pid = data["pid"]
            live_version = data["version"]
            if await self._get_live_pids({pid}):
                return pid, live_version
        except FileNotFoundError:
            pass

        return None, None

    async def teardown_agent(self):
        pid, _ = await self._agent_live()
        if pid is not None:
            await self._kill(pid)

    async def launch_agent(self, pipeline):
        asyncio.get_event_loop().set_debug(True)
        if pipeline.source_file is None:
            raise ValueError("Cannot start a pipeline without a source_file")
            # if you really need this look into forking instead of subprocessing
        pid, version = await self._agent_live()
        if pid is not None:
            if version == pipeline.agent_version:
                return
            await self._kill(pid)

        # lmao, hack
        tmp = os.environ.get("TEMP", "/tmp")
        Path(f"{tmp}/pydatatask-{getpass.getuser()}").mkdir(exist_ok=True, parents=True)
        with open(f"{tmp}/pydatatask-{getpass.getuser()}/agent-stdout-{pipeline.agent_port}", "ab") as fp:
            env = dict(os.environ)
            env["PIPELINE_YAML"] = str(pipeline.source_file)
            p = subprocess.Popen(  # pylint: disable=consider-using-with
                [
                    sys.executable,
                    Path(__file__).parent.parent / "cli" / "main.py",
                    "agent-http",
                ],
                stdin=asyncio.subprocess.DEVNULL,
                stdout=fp,
                stderr=asyncio.subprocess.STDOUT,
                close_fds=True,
                env=env,
            )
            fp.write(
                f"Launched agent version {pipeline.agent_version} pid {p.pid} "
                f"pipeline {pipeline.source_file} port {pipeline.agent_port}".encode()
            )
        agent_path = self._basedir / "agent"
        await self._mkdir(self._basedir)
        data = yaml.safe_dump({"pid": str(p.pid), "version": pipeline.agent_version})
        async with await self._open(agent_path, "w") as fp:
            await fp.write(data)


class LocalLinuxOrKubeManager(LocalLinuxManager):
    """LocalLinuxManager, but also allowed access to the kubernetes configuration on the local machine."""

    def __init__(
        self,
        *,
        quota: Quota = LOCALHOST_QUOTA,
        app: str = "pydatatask",
        image_prefix: str = "",
        nil_ephemeral: Optional[Ephemeral[None]] = None,
        kube_namespace: Optional[str] = None,
        kube_host: Host = Host("LOCAL_KUBE", HostOS.Linux),
        kube_quota: Optional[Quota] = None,
        kube_context: Optional[str] = None,
        kube_volumes: Optional[Dict[str, VolumeSpec]] = None,
        **kwargs,
    ):
        host_path_overrides = {x: y.host_path for x, y in (kube_volumes or {}).items() if y.host_path is not None}
        super().__init__(
            quota=quota,
            app=app,
            image_prefix=image_prefix,
            nil_ephemeral=nil_ephemeral,
            host_path_overrides=host_path_overrides,
            **kwargs,
        )

        if nil_ephemeral is not None:
            self._local_kube: Optional[KubeContainerManager] = KubeContainerManager(
                quota=kube_quota or quota,
                cluster=PodManager(
                    kube_quota or quota,
                    kube_host,
                    app,
                    kube_namespace,
                    nil_ephemeral._session.ephemeral(
                        kube_connect(context=kube_context), name=f"{app}_local_kube", optional=True
                    ),
                    volumes=kube_volumes,
                ),
                image_prefix=image_prefix,
            )
            self._local_kube_set = KubeContainerSetManager(self._local_kube)
        else:
            self._local_kube = None
            self._local_kube_set = None

    def cache_flush(self):
        super().cache_flush()
        if self._local_kube is not None:
            self._local_kube.cache_flush()
        if self._local_kube_set is not None:
            self._local_kube_set.cache_flush()

    def to_pod_manager(self):
        if self._local_kube is not None:
            return self._local_kube.cluster
        raise TypeError("Not configured to connect to kubernetes (pass nil_ephemeral, lol)")

    def to_container_manager(self):
        e1 = None
        if self._local_kube is not None:
            try:
                dir(self._local_kube.cluster.connection)
            except SessionOpenFailedError as e:
                e1 = e
            else:
                return self._local_kube
        try:
            return super().to_container_manager()
        except SessionOpenFailedError as e2:
            if e1 is not None:
                raise e1 from e2
            raise

    def to_container_set_manager(self):
        e1 = None
        if self._local_kube is not None:
            try:
                dir(self._local_kube.cluster.connection)
            except SessionOpenFailedError as e:
                e1 = e
            else:
                return self._local_kube_set
        try:
            return super().to_container_set_manager()
        except SessionOpenFailedError as e2:
            if e1 is not None:
                raise e1 from e2
            raise


class _SSHLinuxFile:
    """A file returned by `SSHLinuxManager.open`.

    Probably don't instantiate this directly.
    """

    def __init__(self, path: Union[Path, str], mode: Literal["r", "w", "rb", "wb"], ssh: "SSHLinuxManager"):
        self.path = Path(path)
        self.mode = mode
        self.ssh = ssh
        self.__fp: Optional[asyncssh.SFTPClientFile] = None
        self.__fp_mgr: Optional[AsyncContextManager[asyncssh.SFTPClientFile]] = None

    @property
    def _fp_mgr(self) -> AsyncContextManager[asyncssh.SFTPClientFile]:
        assert self.__fp_mgr is not None
        return self.__fp_mgr

    @property
    def _fp(self) -> asyncssh.SFTPClientFile:
        assert self.__fp is not None
        return self.__fp

    async def __aenter__(self):
        self.__fp_mgr = self.ssh.sftp.open(self.path, self.mode)
        self.__fp = await self._fp_mgr.__aenter__()
        return self._fp

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._fp_mgr.__aexit__(exc_type, exc_val, exc_tb)


class SSHLinuxManager(AbstractProcessManager):
    """A process manager that runs its processes on a remote linux machine, accessed over SSH. The SSH connection is
    parameterized by an :external:class:`asyncssh.connection.SSHClientConnection` instance.

    Sample usage:

    .. code:: python

        session = pydatatask.Session()

        @session.ephemeral
        async def ssh():
            async with asyncssh.connect(
                "localhost", port=self.port, username="weh", password="weh", known_hosts=None
            ) as s:
                yield s

        @session.ephemeral
        async def procman():
            yield pydatatask.SSHLinuxManager(self.test_id, ssh)

        task = pydatatask.ProcessTask("mytask", procman, ...)
    """

    def __init__(
        self,
        quota: Quota,
        app: str,
        ssh: Ephemeral[asyncssh.SSHClientConnection],
        host: Host,
        remote_path: Union[Path, str] = f"/tmp/pydatatask-{getpass.getuser()}",
    ):
        super().__init__(quota, Path(remote_path) / app)

        @ssh._session.ephemeral
        async def sftp():
            async with ssh().start_sftp_client() as mgr:
                yield mgr

        self._ssh = ssh
        self._sftp = sftp
        self._host = host

    @property
    def host(self):
        return self._host

    @property
    def ssh(self) -> asyncssh.SSHClientConnection:
        """The `asyncssh.SSHClientConnection` instance associated.

        Will fail if the connection is provided by an unopened Session.
        """
        return self._ssh()

    @property
    def sftp(self) -> asyncssh.SFTPClient:
        """The corresponding SFTP client connection.

        Will fail if the connection is provided by an unopened Session.
        """
        return self._sftp()

    @property
    def _basedir(self) -> Path:
        return self._tmp_path

    async def _open(self, path, mode):  # type: ignore
        return _SSHLinuxFile(path, mode, self)

    async def _rmtree(self, path: Path):
        await self.sftp.rmtree(path, ignore_errors=True)  # pylint: disable=no-member

    async def _mkdir(self, path: Path):
        await self.sftp.makedirs(path, exist_ok=True)  # pylint: disable=no-member

    async def _kill(self, pid: str):
        await self.ssh.run(f"kill -9 {pid}")

    async def _readdir(self, path):
        try:
            return [x for x in await self.sftp.listdir(path) if x not in (".", "..")]  # pylint: disable=no-member
        except asyncssh.sftp.SFTPNoSuchFile:
            return []

    async def _chmod(self, path, mode):
        await self.sftp.chmod(path, mode)  # pylint: disable=no-member

    async def _get_live_pids(self, hint):
        p = await self.ssh.run("ls /proc")
        assert p.stdout is not None
        return {cast(str, x) for x in p.stdout.split() if x.isdigit()} & hint

    async def _spawn(self, args, environ, cwd, return_code, stdin, stdout, stderr):
        await self._mkdir(self._tmp_path)
        if stdin is None:
            stdin = "/dev/null"
        else:
            stdin = shlex.quote(str(stdin))
        if stdout is None:
            stdout = "/dev/null"
        else:
            stdout = shlex.quote(str(stdout))
        if stderr is None:
            stderr = "/dev/null"
        elif isinstance(stderr, _StderrIsStdout):
            stderr = "&1"
        else:
            stderr = shlex.quote(str(stderr))
        p = cast(
            asyncssh.SSHClientProcess[bytes],
            await self.ssh.create_process(
                f"""
            cd {shlex.quote(str(cwd))}
            {shlex.join(args)} <{stdin} >{stdout} 2>{stderr} &
            PID=$!
            echo $PID
            wait $PID >/dev/null 2>/dev/null
            echo $? >{shlex.quote(str(return_code))} 2>/dev/null
            """,
                env=environ,
                encoding=None,
            ),
        )
        pid = await p.stdout.readline()
        return pid.strip().decode()


localhost_manager = LocalLinuxManager(quota=LOCALHOST_QUOTA, app="default")


class InProcessLocalLinuxManager(LocalLinuxManager):
    """A process manager for the local linux system which can launch an http agent inside the current process."""

    def __init__(
        self,
        quota: Quota,
        app: str,
        local_path: Union[Path, str] = f"{os.environ.get('TEMP', '/tmp')}/pydatatask-{getpass.getuser()}",
    ):
        super().__init__(quota=quota, app=app, local_path=local_path)

        self.runner: Optional[web.AppRunner] = None

    async def teardown_agent(self):
        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None

    async def launch_agent(self, pipeline):
        if self.runner is not None:
            return
        app = agent.build_agent_app(pipeline)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "localhost", pipeline.agent_port)
        await site.start()
