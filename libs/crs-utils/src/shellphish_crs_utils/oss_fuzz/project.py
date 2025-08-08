from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import string
import subprocess
import tempfile
import time
import base64
import hashlib
from typing import Dict, List, Optional, Tuple, Union
from filelock import FileLock, Timeout

from shellphish_crs_utils.models.crs_reports import (
    BuildTargetResult,
    RunImageResult,
    RunImageInBackgroundResult,
    RunPoVResult,
    RunTestsResult,
    RunOssFuzzBuildCheckResult,
)
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.llvm_symbolizer import LLVMSymbolizerEntry, parse_llvm_symbolizer_json_output_file
from shellphish_crs_utils.models.oss_fuzz_runner_service import (
    ProjectBuildRequest,
    ProjectBuildResult,
    ProjectRunTaskRequest,
    Base64Bytes,
)
from shellphish_crs_utils.models.symbols import BinaryLocation, RelativePathKind, SourceLocation
from shellphish_crs_utils.oss_fuzz.target_info import is_target_path_irrelevant
from shellphish_crs_utils.oss_fuzz.target_runner_service import (
    request_target_build,
    request_target_run,
)
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.pydatatask import PDClient
from shellphish_crs_utils.pydatatask.client import JobStatus
from shellphish_crs_utils.oss_fuzz.quote_unquote_imported.utils import (
    get_fuzz_targets,
    FUZZ_TARGET_SEARCH_STRING,
)
from shellphish_crs_utils.sanitizer_parsers import parse_run_pov_result
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, locate_file_for_function_via_dwarf
import yaml
import shutil
import logging

from shellphish_crs_utils.models.oss_fuzz import (
    LanguageEnum,
    OSSFuzzProjectYAML as OSSFuzzProjectYAML,
    AugmentedProjectMetadata,
)
from shellphish_crs_utils.models.constraints import PDT_ID
from shellphish_crs_utils.oss_fuzz.quote_unquote_imported.helper import docker_run
from crs_telemetry.utils import init_otel, get_otel_tracer

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

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "dynamic_analysis", "oss_fuzz.analyze_projects")
tracer = get_otel_tracer()

os.environ["USING_CRS_UTILS"] = "1"
LOG_FORMAT = (
    "%(asctime)s [%(levelname)-8s] "
    "%(name)s:%(lineno)d | %(message)s"
)
logging.basicConfig(
    format=LOG_FORMAT, level=logging.INFO
)
logger = logging.getLogger(__name__)
CACHED_BUILD_DIR = Path("/shared/target_build_cache")

FORBID_LOCAL_RUN = False
FORBID_SERVICE_RUN = False

def is_in_k8s():
    return os.environ.get("IN_K8S", None) is not None

class DockerService:
    DOCKER_IS_READY = False

    @classmethod
    def wait_until_docker_is_ready(cls, sleep_seconds: int = 10, max_retries: int = 12):
        if cls.DOCKER_IS_READY:
            return True

        for i in range(max_retries):
            is_ready = False
            try:
                out = subprocess.check_output(["docker","info","-f","json"], env={**os.environ, 'SILENCE_DOCKER_WARNING': '1'})
                info = json.loads(out)
                is_ready = False
                if info.get("ServerVersion", None):
                    is_ready = True

                # If we see server errors give it a bit to clear
                if info.get("ServerErrors", None) and i < max_retries/2:
                    is_ready = False

            except Exception as e:
                logger.warning("Error checking docker status: %s", e)
                is_ready = False

            if is_ready:
                cls.DOCKER_IS_READY = True
                return True

            logger.warning("Docker is not ready, retrying in %d seconds (%d/%d retries)", sleep_seconds, i+1, max_retries)
            time.sleep(sleep_seconds)
            continue

        logger.warning("Docker is not ready after %d seconds", max_retries * sleep_seconds)
        return False

    @classmethod
    def __prep_call_args(cls, args: List[str]) -> List[str]:
        args = list(args)
        if len(args) == 0:
            raise ValueError("No arguments provided to DockerService call")
        if args[0] != "docker":
            args = ["docker"] + args
        return args

    @classmethod
    def __run_with_retries(cls, target_func, cmd: List[str], retries=0, retry_backoff_seconds=60, **kwargs):
        for i in range(retries + 1):
            try:
                logger.info("+ %s", ' '.join(cmd))
                return target_func(cmd, **kwargs)
            except subprocess.CalledProcessError:
                if i >= retries:
                    raise
                logger.warning("Failed to run %s, retrying in %d seconds (%d/%d retries)", cmd, retry_backoff_seconds, i+1, retries)
                time.sleep(retry_backoff_seconds)
                continue

    @classmethod
    def call(cls, *args, **kwargs):
        args = cls.__prep_call_args(args)
        DockerService.wait_until_docker_is_ready()
        return cls.__run_with_retries(subprocess.check_call, args, **kwargs)

    @classmethod
    def output(cls, *args, **kwargs):
        args = cls.__prep_call_args(args)
        DockerService.wait_until_docker_is_ready()
        return cls.__run_with_retries(subprocess.check_output, args, **kwargs)

    @classmethod
    def lock_image_creation(cls, image_name: str, timeout=300):
        lock_name = image_name.replace("/", "_")
        lock_dir = '/tmp/docker-locks'
        if os.path.exists('/shared'):
            try:
                os.makedirs('/shared/docker-locks', exist_ok=True)
                lock_dir = '/shared/docker-locks'
            except Exception as e:
                pass
        os.makedirs(lock_dir, exist_ok=True)
        lock_path = f'{lock_dir}/{lock_name}.lock'
        return optional_filelock(lock_path, timeout=timeout)


class OSSFuzzProject:
    RUN_TESTS_SCRIPT = "test.sh"

    def __init__(
        self,
        oss_fuzz_project_path: Path,
        project_source: Path = None,
        project_id: PDT_ID = None,
        augmented_metadata: AugmentedProjectMetadata = None,
        pdclient=None,
        use_task_service=False,
    ):
        self.project_path = Path(oss_fuzz_project_path).absolute().resolve()
        self.project_source = project_source
        self.project_id = project_id
        self.augmented_metadata = augmented_metadata
        self.docker_build_secret = None
        self.build_with_no_cache = False
        self.build_with_no_compiler_cache = False
        self.docker_image_prefix = (
            os.environ.get("DOCKER_IMAGE_PREFIX", "") + "shellphish-"
        )

        self.artifacts_dir_docker.mkdir(parents=True, exist_ok=True)

        assert self.dockerfile_path.exists(), (
            f"Dockerfile {self.dockerfile_path} does not exist"
        )
        # assert (self.project_path / 'build.sh').exists(), f"Build script {self.project_path / 'build.sh'} does not exist"

        with open(self.project_yaml_path, "r") as f:
            self.project_metadata = OSSFuzzProjectYAML.model_validate(yaml.safe_load(f))

        self._container_workdir = None
        self._build_metadata = None

        self.pdclient = pdclient
        self.use_task_service = use_task_service
        if use_task_service:
            # assert pdclient is not None, "PDClient must be provided if use_task_service is True"
            # for later, here's how we would set it up
            self.pdclient = PDClient.from_env()

    def oss_fuzz_base_builder_image(self):
        return os.environ.get("OSS_FUZZ_BASE_BUILDER_IMAGE", "ghcr.io/aixcc-finals/base-builder:v1.3.0")

    def set_docker_build_secret(self, secret):
        # This is for handling with private targets in our SSS repo.
        self.docker_build_secret = secret

    def no_cache(self):
        self.build_with_no_cache = True

    def no_compiler_cache(self):
        self.build_with_no_compiler_cache = True

    def set_artifacts_output_path(self, out_path: Path):
        self.artifacts_out_path = out_path

    @property
    def project_name(self) -> str:
        return self.project_metadata.get_project_name()

    @property
    def project_language(self) -> LanguageEnum:
        return self.project_metadata.language

    @property
    def artifacts_dir_docker(self) -> Path:
        assert self.artifacts_dir is not None, (
            "Output path not set, call __enter__ first"
        )
        return self.artifacts_dir / "docker"

    @property
    def artifacts_dir_docker_runs(self):
        assert self.project_path is not None, (
            "Output path not set, call __enter__ first"
        )
        return self.artifacts_dir_docker / "runs"

    # @property
    # def out_dir_src(self) -> Path:
    #     assert self.project_path is not None, "Output path not set, call __enter__ first"
    #     return self.project_path / 'src'

    @property
    def artifacts_dir(self) -> Path:
        return self.project_path / "artifacts"

    @property
    def artifacts_dir_work(self) -> Path:
        return self.artifacts_dir / "work"

    @property
    def artifacts_dir_out(self) -> Path:
        return self.artifacts_dir / "out"

    @property
    def artifacts_dir_built_src(self) -> Path:
        """
        This is the directory where we store the /src/ directory after building. This is only populated when a target is built with
        the preserve_built_src_dir flag set to True.
        """
        return self.artifacts_dir / "built_src"

    @property
    def dockerfile_path(self) -> Path:
        return self.project_path / "Dockerfile"

    @property
    def shared_dir(self) -> Path:
        return Path("/shared")

    def tmp_shm_dir(self, instance_name) -> Path:
        return Path("/dev/shm/fuzztmp/" + instance_name)

    @property
    def project_yaml_path(self) -> Path:
        return self.project_path / "project.yaml"

    def is_path_generated_during_build(self, artifact_path: Path=None, container_path: Path=None, focus_repo_rel_path: Path=None) -> bool:
        if focus_repo_rel_path is not None:
            focus_repo_rel_path = None if focus_repo_rel_path is None else Path(focus_repo_rel_path)
            assert not focus_repo_rel_path.is_absolute() and (self.get_focus_repo_artifacts_path() / focus_repo_rel_path).exists(), f"Path {focus_repo_rel_path} is not relative to the focus repo"
            assert self.project_source is not None, "Project source must be set to use this function"
            return not (self.project_source / focus_repo_rel_path).exists()

        if container_path is not None:
            container_path = Path(container_path)
            artifact_path = self.artifacts_path(container_path=container_path)

        assert artifact_path is not None and artifact_path.is_absolute() and artifact_path.exists() and artifact_path.is_relative_to(self.artifacts_dir), f"Path {artifact_path} is not a valid artifact path"
        # For now, just return False
        focus_repo_rel_path = self.focus_repo_rel_path(artifact_path=artifact_path)
        if not focus_repo_rel_path:
            return False # Not in the focus repo, assume not generated during build

        return self.is_path_generated_during_build(focus_repo_rel_path=focus_repo_rel_path)

    def artifacts_rel_path(self, container_path: Union[Path, str]):
        container_path = Path(container_path)
        prefix = {
            '/src/': self.artifacts_dir_built_src,
            '/work/': self.artifacts_dir_work,
            '/out/': self.artifacts_dir_out
        }
        for k, v in prefix.items():
            if container_path.is_relative_to(k):
                return (Path(v) / container_path.relative_to(k)).relative_to(self.artifacts_dir)

        if artiphishell_should_fail_on_error():
            logger.error(f"Path {container_path} is not relative to any of the known artifact directories")
            raise ValueError(f"Path {container_path} is not relative to any of the known artifact directories")
        else:
            # This is a fallback for when we are not in the shellphish environment
            # We just return the path as is, but this may cause issues later on
            # So be careful with this
            logger.warning(f"Path {container_path} is not relative to any of the known artifact directories, returning it as is just to be safe. This assumes that all dependencies are also available in the current environment")
            return container_path

    def artifacts_path(self, container_path: Union[Path, str]):
        return self.artifacts_dir / self.artifacts_rel_path(container_path)

    def focus_repo_rel_path(self, container_path=None, artifact_path=None) -> Optional[Path]:
        if container_path:
            assert any(container_path.is_relative_to(v) for v in ['/src/', '/work/', '/out/'])
            container_path = Path(container_path)
            focus_repo_container_path = self.get_focus_repo_container_path()
            if container_path.is_relative_to(focus_repo_container_path):
                return container_path.relative_to(focus_repo_container_path)
            return None

        elif artifact_path:
            artifact_path = Path(artifact_path)
            assert artifact_path.is_absolute()
            base = self.get_focus_repo_artifacts_path()
            if artifact_path.is_relative_to(base):
                return artifact_path.relative_to(base)
            return None
        else:
            raise ValueError("Either container_path or artifact_path must be provided")

    def target_container_path(self, in_focus_repo_relative_path: Path=None, artifact_path: Path=None) -> Path:
        if in_focus_repo_relative_path:
            assert not in_focus_repo_relative_path.is_absolute()
            return self.get_focus_repo_container_path() / in_focus_repo_relative_path

        elif artifact_path:
            assert artifact_path.is_absolute() and artifact_path.is_relative_to(self.artifacts_dir)
            if artifact_path.is_relative_to(self.artifacts_dir_built_src):
                return Path('/src/') / artifact_path.relative_to(self.artifacts_dir_built_src)
            elif artifact_path.is_relative_to(self.artifacts_dir_work):
                return Path('/work/') / artifact_path.relative_to(self.artifacts_dir_work)
            elif artifact_path.is_relative_to(self.artifacts_dir_out):
                return Path('/out/') / artifact_path.relative_to(self.artifacts_dir_out)
            else:
                raise ValueError(f"Unknown artifact path {artifact_path}")

        else:
            raise ValueError("Either focus_repo_path or artifact_path must be provided")

    def get_focus_repo_container_path(self) -> Path:
        return self.get_builder_workdir()

    def get_focus_repo_artifacts_path(self) -> Path:
        return self.artifacts_dir / self.artifacts_rel_path(self.get_focus_repo_container_path())

    def is_source_container_path_relevant(self, container_path: Union[str, Path]) -> bool:
        return not is_target_path_irrelevant(Path(container_path), self.get_focus_repo_container_path())

    def get_shellphish_build_metadata(self):
        if self._build_metadata is None:
            if (self.artifacts_dir_out / "shellphish_build_metadata.yaml").exists():
                with open(self.artifacts_dir_out / "shellphish_build_metadata.yaml") as f:
                    metadata = yaml.safe_load(f)
                    self._build_metadata = metadata
        return self._build_metadata


    def get_built_sanitizer(self) -> Optional[str]:
        sanitizer = None
        if meta := self.get_shellphish_build_metadata():
            sanitizer = meta.get("sanitizer", None)
        # If we don't have a sanitizer, we leave it up to the caller to determine what to do. Generally, either
        # a) they already know what it was since they built and ran it
        # b) they don't care, in which case they should just use the default (e.g. the first in the supported sanitizers list)
        return sanitizer


    def get_builder_workdir(self, pull: bool = False):
        if self._container_workdir is None:
            # Strategy one: check, if we have a `artifacts/out/shellphish_build_metadata.yaml` file
            # and if so, read the `source_repo_path` field
            if (metadata := self.get_shellphish_build_metadata()) and "source_repo_path" in metadata:
                self._container_workdir = Path(metadata["source_repo_path"])
                return self._container_workdir

            # Strategy two: get it from the builder
            name = self.build_builder_image()
            if pull or is_in_k8s():
                self.docker_pull(name)

            out = DockerService.output("inspect", name, "--format", "{{.Config.WorkingDir}}")
            self._container_workdir = Path(out.decode().strip())
        return self._container_workdir

    def get_runner_workdir(self, pull: bool = False):
        if self._container_workdir is None:
            name = self.get_runner_image_name()
            if pull or is_in_k8s():
                self.docker_pull(name)

            out = DockerService.output("inspect", name, "--format", "{{.Config.WorkingDir}}")
            self._container_workdir = Path(out.decode().strip())
        return self._container_workdir

    def get_base_builder_image_name(self, commit_hash: str = None):
        if commit_hash:
            return (
                self.docker_image_prefix
                + f"oss-fuzz-builder-{self.project_name.lower()}-{commit_hash}"
            )
        else:
            return (
                self.docker_image_prefix
                + f"oss-fuzz-builder-{self.project_name.lower()}"
            )

    def get_builder_image_name(self, commit_hash: str = None):
        return self.get_base_builder_image_name(commit_hash)

    def get_base_runner_image_name(self):
        return self.docker_image_prefix + f"oss-fuzz-runner-{self.project_name.lower()}"

    def get_runner_image_name(self):
        return self.get_base_runner_image_name()

    def docker_build_image_extract_sources(
        self, src_dir: Path, work_dir: Path, out_dir: Path
    ):
        src_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        copy_commands = [
            f"cp -raT /{directory}/ /shellphish_out_{directory}"
            for directory in ["src", "work", "out"]
        ]

        cmd = " && ".join(copy_commands)
        final_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{src_dir}:/shellphish_out_src",
            "-v",
            f"{work_dir}:/shellphish_out_work",
            "-v",
            f"{out_dir}:/shellphish_out_out",
            self.get_builder_image_name(),
            "/bin/bash",
            "-c",
            cmd,
        ]
        print("Extracting sources with command:", final_cmd)
        DockerService.call(*final_cmd)

    @tracer.start_as_current_span("docker_build")
    def docker_build(
        self, image_name: str, dockerfile: Path, context_dir: Path, *args, push=False
    ):
        logger.info(f"📦🔒 Aquiring lock to build {image_name}")
        with DockerService.lock_image_creation(image_name, timeout=600) as got_lock:
            if not got_lock:
                logger.warning(f"📦⚠️ Couldn't acquire lock for {image_name}, proceeding anyway")
            return self._docker_build_impl(image_name, dockerfile, context_dir, *args, push=push)

    def _docker_build_impl(
        self, image_name: str, dockerfile: Path, context_dir: Path, *args, push=False
    ):
        assert dockerfile.exists(), f"Dockerfile {dockerfile} does not exist"
        print(
            f"Building {image_name} with Dockerfile {dockerfile} in {context_dir} with args {args}"
        )

        if self.docker_build_secret:
            # add the secret
            args += ("--secret", self.docker_build_secret)
        elif os.environ.get("GITHUB_CREDS_PATH"):
            # This path is in the docker daemon's fs
            args += (
                "--secret",
                f"id=GITHUB_CRED_URL,src={os.environ['GITHUB_CREDS_PATH']}",
            )

        build_cmd = ["docker", "build"]

        if self.build_with_no_cache:
            args += ("--no-cache",)

        elif os.environ.get("OSS_FUZZ_CACHE_TARGET_BUILDS", "").lower() in [
            "1",
            "t",
            "true",
            "y",
            "yes",
        ]:

            # First make sure we are using the correct docker buildx daemon
            can_use_cache = False
            try:
                DockerService.call(
                    "buildx",
                    "create",
                    "--driver",
                    "docker-container",
                    "--name",
                    "cached-builder",
                    env={**os.environ, 'SILENCE_DOCKER_WARNING': '1'}
                )
            except subprocess.CalledProcessError:
                # This may fail if it already exists
                pass

            try:
                DockerService.call("buildx", "use", "cached-builder", env={**os.environ, 'SILENCE_DOCKER_WARNING': '1'})
                can_use_cache = True
            except subprocess.CalledProcessError:
                can_use_cache = False
                pass

            if can_use_cache:
                # To cache the target image builds, we need to use buildx
                # which supports the cache-to and cache-from options
                build_cmd = ["docker", "buildx", "build"]

                cache_name = image_name.split(":")[0] + ":cache"
                cache_prefix = os.environ.get("OSS_FUZZ_CACHE_PREFIX", None)
                if cache_prefix:
                    if self.docker_image_prefix and "/" in self.docker_image_prefix:
                        no_prefix = (cache_name.split("/", 1) + [cache_name])[1]
                        cache_name = cache_prefix.strip("/") + "/" + no_prefix
                    else:
                        cache_name = cache_prefix.strip("/") + "/" + cache_name

                args += (
                    "--cache-to",
                    f"type=registry,ref={cache_name},mode=max,ignore-error=true",
                    "--cache-from",
                    f"type=registry,ref={cache_name}",
                )
                if not is_in_k8s():
                    # The k8s setup is that we always pull and push images
                    # So we do not rely on them being present locally
                    # So we can save some time by avoiding the load step
                    args += ("--load",)

        if push:
            args += ("--push",)

        DockerService.call(
            *build_cmd,
            "-t",
            image_name,
            "-f",
            str(dockerfile),
            *args,
            str(context_dir),
        )
        return image_name

    def _run_cmd_with_retries(self, cmd: List[str], retries=3, retry_backoff_seconds=60):
        for i in range(retries):
            try:
                return subprocess.check_output(cmd)
            except subprocess.CalledProcessError:
                print(f"Failed to run {cmd}, retrying in {retry_backoff_seconds} seconds")
                time.sleep(retry_backoff_seconds)
                if i < retries - 1:
                    continue
                else:
                    raise

    @tracer.start_as_current_span("docker_pull")
    def docker_pull(self, image_name: str, retries=3, retry_backoff_seconds=60):
        logger.info(f"📦🔒 Aquiring lock to pull {image_name}")
        with DockerService.lock_image_creation(image_name, timeout=600) as got_lock:
            if not got_lock:
                logger.warning(f"📦⚠️ Couldn't acquire lock for {image_name}, proceeding anyway")
            print(f"Pulling {image_name}")
            DockerService.call(
                "pull",
                image_name,
                retries=retries, retry_backoff_seconds=retry_backoff_seconds
            )
            return image_name

    @tracer.start_as_current_span("docker_push")
    def docker_push(self, image_name: str, retries=3, retry_backoff_seconds=60):
        print(f"Pushing {image_name}")
        DockerService.call(
            "push",
            image_name,
            retries=retries, retry_backoff_seconds=retry_backoff_seconds
        )
        return image_name

    def docker_tag(self, source_image: str, target_image: str, pull=False, push=False, retries=3, retry_backoff_seconds=60):
        print(f"Tagging {source_image} as {target_image}")
        if pull:
            self.docker_pull(source_image, retries=retries, retry_backoff_seconds=retry_backoff_seconds)

        DockerService.call("tag", source_image, target_image)
        if push:
            self.docker_push(target_image, retries=retries, retry_backoff_seconds=retry_backoff_seconds)
        return target_image

    def ensure_image_exists(self, image_name: str, retries=3, retry_backoff_seconds=60):
        """
        Ensure that the image exists locally. If it does not, try to pull it.
        If pull is True, it will try to pull the image from the registry.
        If push is True, it will try to push the image to the registry.
        """
            # ensure the image exists, otherwise try to pull it
        try:
            DockerService.output("inspect", image_name, "--format", "{{.Id}}")
            return image_name
        except subprocess.CalledProcessError:
            print(f"Image {image_name} not found, trying to pull it")
            self.docker_pull(image_name, retries=retries, retry_backoff_seconds=retry_backoff_seconds)
            return image_name


    @tracer.start_as_current_span("image_run__local")
    def image_run__local(self, image_name, *cmd: List[str], timeout=None, volumes: Dict[Path, str]=None, extra_env: Dict[str, str]=None, extra_docker_args: List[str]=None, print_output=True) -> RunImageResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        self.ensure_image_exists(image_name, retries=100) # this REALLY should not fail as we expect the image to exist locally if we're trying to run it

        volumes = volumes or {}

        # These should always be mapped!
        volumes.update(
            {
                # self.out_dir_src: '/src',
                self.artifacts_dir_work: "/work",
                self.artifacts_dir_out: "/out",
            }
        )

        volume_args = []
        for host_path, container_path in volumes.items():
            volume_args += ["-v", f"{host_path}:{container_path}"]

        docker_runs_dir = self.artifacts_dir_docker_runs
        docker_cur_run_dir = (
            docker_runs_dir
            / f"run_in_builder_{int(time.time())}_{hashlib.sha1(os.urandom(32)).hexdigest()}"
        )
        docker_cur_run_dir.mkdir(parents=True, exist_ok=True)

        final_cmd = volume_args
        if extra_env:
            env_file = docker_cur_run_dir / ".docker.env"
            with open(env_file, "w") as f:
                for k, v in extra_env.items():
                    f.write(f"{k}={v}\n")

            final_cmd += ["--env-file", str(env_file)]
        final_cmd += [
            "--cidfile",
            str(docker_cur_run_dir / "container.id"),
        ]
        final_cmd += extra_docker_args or []

        final_cmd += [image_name]
        if timeout is not None:
            final_cmd += (
                f"timeout --preserve-status -s KILL {timeout + 3} timeout -sINT {timeout + 2} ".split()
            )
        final_cmd += cmd

        # temporarily set an env var to the log file
        rand_string = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=10)
        )
        container_name = (
            f"shellphish_{self.project_name}_builder_{int(time.time())}_{rand_string}"
        )
        prev_val = os.environ.get("OSS_FUZZ_SAVE_CONTAINERS_NAME", container_name)
        os.environ["OSS_FUZZ_SAVE_CONTAINERS_NAME"] = container_name
        time_start = time.time()

        # Since we are using the "oss-fuzz" docker_run command instead of the docker service, we need to manually wait until the docker daemon is ready
        DockerService.wait_until_docker_is_ready()

        docker_exit_code = docker_run(final_cmd, print_output=print_output, propagate_exit_codes=True)
        logger.info(f"Docker run finished with exit code {docker_exit_code} for container {container_name}")
        docker_success = docker_exit_code == 0
        time_end = time.time()
        os.environ["OSS_FUZZ_SAVE_CONTAINERS_NAME"] = prev_val

        # get the logs of stdout and stderr
        stdout_path = docker_cur_run_dir / "stdout.log"
        stderr_path = docker_cur_run_dir / "stderr.log"
        with open(stdout_path, "w") as f:
            with open(stderr_path, "w") as g:
                DockerService.call("logs", container_name, stdout=f, stderr=g)

        result = {}
        result['run_exit_code'] = docker_exit_code
        result["task_success"] = docker_success
        result["time_scheduled"] = time_start
        result["time_start"] = time_start
        result["time_end"] = time_end
        result["time_taken"] = time_end - time_start

        with open(stdout_path, "r") as f:
            result["stdout"] = f.read()
        with open(stderr_path, "r") as f:
            result["stderr"] = f.read()

        with open(docker_cur_run_dir / "container.id", "r") as f:
            result["container_id"] = f.read().strip()

        run_exit_code = DockerService.output("inspect", result["container_id"], "--format", "{{.State.ExitCode}}")

        result["run_exit_code"] = run_exit_code
        result["container_name"] = container_name
        result["out_dir"] = docker_cur_run_dir

        DockerService.call("rm", container_name)

        return RunImageResult(**result)

    @tracer.start_as_current_span("image_run_background__local")
    def image_run_background__local(
        self,
        image_name,
        *cmd: List[str],
        timeout=None,
        volumes: Dict[Path, str] = None,
        extra_env: Dict[str, str] = None,
        extra_docker_args: List[str] = None,
    ) -> RunImageInBackgroundResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        self.ensure_image_exists(image_name, retries=100) # this REALLY should not fail as we expect the image to exist locally if we're trying to run it

        volumes = volumes or {}

        # These should always be mapped!
        volumes.update(
            {
                # self.out_dir_src: '/src',
                self.artifacts_dir_work: "/work",
                self.artifacts_dir_out: "/out",
            }
        )

        volume_args = []
        for host_path, container_path in volumes.items():
            volume_args += ["-v", f"{host_path}:{container_path}"]

        docker_runs_dir = self.artifacts_dir_docker_runs
        docker_cur_run_dir = (
            docker_runs_dir
            / f"run_in_builder_{int(time.time())}_{hashlib.sha1(os.urandom(32)).hexdigest()}"
        )
        docker_cur_run_dir.mkdir(parents=True, exist_ok=True)

        final_cmd = volume_args
        if extra_env:
            env_file = docker_cur_run_dir / ".docker.env"
            with open(env_file, "w") as f:
                for k, v in extra_env.items():
                    f.write(f"{k}={v}\n")

            final_cmd += ["--env-file", str(env_file)]

        # NOTE: this is using the -d flag to run the docker in detached mode
        final_cmd += [
            "-d",
            "--cidfile",
            str(docker_cur_run_dir / "container.id"),
        ]
        final_cmd += extra_docker_args or []

        final_cmd += [image_name]
        if timeout is not None:
            final_cmd += (
                f"timeout -s KILL {timeout + 1} timeout -sINT {timeout} ".split()
            )
        final_cmd += cmd

        # temporarily set an env var to the log file
        rand_string = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=10)
        )
        container_name = (
            f"shellphish_{self.project_name}_builder_{int(time.time())}_{rand_string}"
        )
        prev_val = os.environ.get("OSS_FUZZ_SAVE_CONTAINERS_NAME", container_name)
        os.environ["OSS_FUZZ_SAVE_CONTAINERS_NAME"] = container_name
        time_start = time.time()

        # Since we are using the "oss-fuzz" docker_run command instead of the docker service, we need to manually wait until the docker daemon is ready
        DockerService.wait_until_docker_is_ready()

        docker_success = docker_run(final_cmd, print_output=True)

        time_end = time.time()
        os.environ["OSS_FUZZ_SAVE_CONTAINERS_NAME"] = prev_val

        result = {}
        result["task_success"] = docker_success
        result["time_scheduled"] = time_start
        result["time_start"] = time_start

        assert docker_success, (
            f"Docker {container_name} did not start correctly (out_dir {docker_cur_run_dir}) [docker_cmd: {final_cmd}]"
        )
        assert (docker_cur_run_dir / "container.id").exists(), (
            f"Container ID file does not exist. Docker {container_name} did not start correctly (out_dir {docker_cur_run_dir}) [docker_cmd: {final_cmd}]"
        )

        with open(docker_cur_run_dir / "container.id", "r") as f:
            result["container_id"] = f.read().strip()
        result["container_name"] = container_name

        run_exit_code = DockerService.output("inspect", result["container_id"], "--format", "{{.State.ExitCode}}")
        result["run_exit_code"] = run_exit_code

        result["out_dir"] = docker_cur_run_dir

        return RunImageInBackgroundResult(**result)


    # @tracer.start_as_current_span("image_run__service")
    # def image_run__service(self, image_name, *cmd: List[str], sanitizer=None, fuzzing_engine=None, timeout=None, volumes: Dict[Path, str]=None, extra_env: Dict[str, str]=None, extra_docker_args: List[str]=None, artifact_globs: List[str] = None, print_output=True) -> RunImageResult:
    #     assert not FORBID_SERVICE_RUN, "Service runs are forbidden"

    #     pdclient = self.pdclient

    #     extra_env = extra_env or {}
    #     request = ProjectRunTaskRequest(
    #         project_id=self.project_id,
    #         project_language=self.project_language.value,
    #         docker_image=image_name,
    #         sanitizer=sanitizer or 'address',
    #         fuzzing_engine=fuzzing_engine or 'libfuzzer',
    #         env=extra_env,
    #         timeout=timeout,
    #         command=cmd,
    #         volumes_id=None,
    #         collect_artifacts=bool(
    #             artifact_globs
    #         ),  # if we have artifact globs, we want to collect artifacts
    #         output_artifacts_globs=artifact_globs,
    #     )

    #     time_submitted = datetime.now(tz=timezone.utc)
    #     result = request_target_run(request, volumes, pdclient)
    #     assert result.was_submitted()
    #     logger.info("Run submitted")
    #     result.await_completion()
    #     logger.info("Run completed")
    #     status, meta = result.get_status()
    #     if status == JobStatus.TIMEOUT:
    #         raise TimeoutError("The run task timed out")
    #     elif status == JobStatus.FAILURE:
    #         raise RuntimeError("The run task failed")

    #     run_result = result.get_run_result()

    #     assert status == JobStatus.SUCCESS, f"Unexpected status {status}"
    #     end_time: datetime = meta["end_time"]
    #     start_time: datetime = meta["start_time"]
    #     success = meta["success"]
    #     run_exit_code = run_result.run_exit_code
    #     timeout = meta["timeout"]

    #     stdout = result.get_run_stdout()
    #     stderr = result.get_run_stderr()

    #     return RunImageResult(
    #         task_success=success,
    #         run_exit_code=run_exit_code,
    #         time_scheduled=time_submitted.timestamp(),
    #         time_start=start_time.timestamp(),
    #         time_end=end_time.timestamp(),
    #         time_taken=(end_time - start_time).total_seconds(),
    #         stdout=stdout,
    #         stderr=stderr,
    #     )

    @tracer.start_as_current_span("image_run")
    def image_run(self, image_name, *cmd: List[str], timeout=None, volumes: Dict[Path, str]=None, extra_env: Dict[str, str]=None, extra_docker_args: List[str]=None, force_local_run: bool = False, print_output: bool = True) -> RunImageResult:
        # if self.use_task_service and not force_local_run:
        #     return self.image_run__service(image_name, *cmd, timeout=timeout, volumes=volumes, extra_env=extra_env, extra_docker_args=extra_docker_args, print_output=print_output)
        # else:
        return self.image_run__local(image_name, *cmd, timeout=timeout, volumes=volumes, extra_env=extra_env, extra_docker_args=extra_docker_args, print_output=print_output)

    @tracer.start_as_current_span("builder_image_run")
    def builder_image_run(self, *cmd: List[str], **kwargs):
        return self.image_run(self.get_builder_image_name(), *cmd, **kwargs)

    @tracer.start_as_current_span("runner_image_run")
    def runner_image_run(self, *cmd: List[str], **kwargs):
        return self.image_run(self.get_runner_image_name(), *cmd, **kwargs)

    @tracer.start_as_current_span("build_builder_image")
    def build_builder_image(
        self,
        image_name: str = None,
        dockerfile: Path = None,
        context_dir: Path = None,
        push: bool = False,
    ):
        image_name = image_name or self.get_base_builder_image_name()
        dockerfile = dockerfile or self.dockerfile_path
        context_dir = context_dir or self.project_path
        if self.project_metadata.is_prebuilt():
            return self.docker_tag(
                self.project_metadata.get_docker_image_name(self.project_name),
                image_name,
                pull=is_in_k8s(),
                push=push,
            )
        else:
            # First try to pull the image from the registry before we attempt to build it
            if is_in_k8s():
                try:
                    self.docker_pull(image_name, retries=0)
                    return image_name
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    logger.warning(f"📦🛠️ Image {image_name} not found in registry, building it: {e}")

            return self.docker_build(
                image_name,
                self.dockerfile_path,
                self.project_path,
                push=push,
            )

    @tracer.start_as_current_span("build_runner_image")
    def build_runner_image(self, push: bool = False, pull: bool=False):
        image_name = self.get_base_runner_image_name()
        return self.docker_tag(
            "ghcr.io/aixcc-finals/base-runner:v1.3.0",
            image_name,
            pull=is_in_k8s() or pull,
            push=push,
        )

    def wipe_artifacts_dirs(self):
        shutil.rmtree(self.artifacts_dir, ignore_errors=True)

    def create_artifacts_dirs(self):
        self.artifacts_dir_docker_runs.mkdir(parents=True, exist_ok=True)
        # self.out_dir_src.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir_work.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir_work.mkdir(parents=True, exist_ok=True)

    def reset_artifacts_dirs(self):
        self.wipe_artifacts_dirs()
        self.create_artifacts_dirs()
        # self.docker_build_image_extract_sources(self.out_dir_src, self.out_dir_work, self.out_dir_out)

    def post_build_commands(self) -> List[str]:
        return [
            '''find "$OUT" -type f -maxdepth 1 -exec sh -c 'set -x; if readelf -h "$1" | grep -q "ELF Header:" && grep -q LLVMFuzzerTestOneInput "$1"; then echo "Processing: $1"; harness_address=$(llvm-nm "$1" | grep LLVMFuzzerTestOneInput | awk '"'"'{print "0x"$1}'"'"'); echo "$harness_address" > "$1.shellphish_harness_address.txt"; llvm-symbolizer --obj="$1" --output-style=JSON "$harness_address" > "$1.shellphish_harness_symbols.json"; fi' _ {} \;'''
        ] + [
            f'cp $(which {bin}) "$OUT/"' for bin in ['llvm-nm', 'llvm-cov', 'llvm-objcopy']
        ]

    def get_build_command(self, preserve_built_src_dir: bool = False) -> List[str]:

        ccache_configuration: str = ''

        if self.build_with_no_compiler_cache or os.environ.get('ARTIPHISHELL_CCACHE_DISABLE', '0') == '1':
            ccache_configuration += 'export CCACHE_DISABLE=1; \
                                     export ARTIPHISHELL_CCACHE_DISABLE="1"'
        else:
            ccache_configuration = 'if [[ "$ARTIPHISHELL_CCACHE_DISABLE" != "1" ]]; then ' + \
                                'ln -sf /usr/local/bin/ccache /ccache/bin/gcc; ' + \
                                'ln -sf /usr/local/bin/ccache /ccache/bin/g++; ' + \
                                'export CCACHE_DIR="/shared/ccache"; ' + \
                                'export CCACHE_MAXSIZE="100G"; ' + \
                                'export CMAKE_C_COMPILER_LAUNCHER=ccache; ' + \
                                'export CMAKE_CXX_COMPILER_LAUNCHER=ccache; ' + \
                                'export PATH="/ccache/bin:$PATH"; ' + \
                                'fi; '

        build_vars_check = 'echo "Compiling with $(which $CC)"; '

        cmd_inner = ccache_configuration + \
                    build_vars_check + \
                    'compile; RETCODE=$?; '

        pbc = self.post_build_commands()
        if preserve_built_src_dir:
            pbc = ['cp -r /src /out/.shellphish_src'] + pbc

        if pbc:
            cmd_inner += '; '.join(pbc) + '; '

        cmd_inner += 'set -x; exit $RETCODE'
        cmd = ["bash", "-c", cmd_inner]
        return cmd

    @tracer.start_as_current_span("build_target__local")
    def build_target__local(
        self,
        patch_content: str = None,
        patch_path: Path = None,
        git_ref: str = None,
        fuzzing_engine: str = None,
        sanitizer: str = None,
        extra_env: Dict[str, str] = None,
        print_output: bool = True,
        preserve_built_src_dir: bool = False,
        extra_files: Dict[str, str] = None,
        custom_build_command: List[str] = None,
        timeout: int = None,
        **extra_kwargs
                            ) -> BuildTargetResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        assert not patch_content or not patch_path, (
            "Only one of patch_content or patch_path should be provided"
        )

        # assert (not patch_content) and (not patch_path), "patch building is currently not supported in local mode"

        self.artifacts_dir_docker.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir_out.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir_work.mkdir(parents=True, exist_ok=True)

        if patch_content:
            patch_path = self.artifacts_dir_docker / f"patch_{time.time()}.diff"
            with open(patch_path, "w") as f:
                f.write(patch_content)

        project_source_to_mount = self.project_source
        mount_tmp_dir = None
        if project_source_to_mount:
            self.artifacts_dir_docker.mkdir(parents=True, exist_ok=True)
            mount_tmp_dir = tempfile.TemporaryDirectory(
                dir=self.artifacts_dir_docker, prefix="project_source_mount_"
            ).name
            subprocess.check_call(
                [
                    "rsync",
                    "-ra",
                    str(project_source_to_mount) + "/",
                    str(mount_tmp_dir) + "/",
                ]
            )
            project_source_to_mount = Path(mount_tmp_dir)
        if git_ref:
            subprocess.check_call(
                ["git", "reset", "--hard", git_ref], cwd=mount_tmp_dir
            )
        if patch_path:
            assert mount_tmp_dir, "Project source must be provided to apply patch and must be mounted from a temporary directory"
            subprocess.check_call(
                ["git", "apply", str(Path(patch_path).resolve()), "-v"], cwd=mount_tmp_dir
            )

        # self.build_builder_image()
        # self.reset_build_dirs()

        real_env = {
            "FUZZING_LANGUAGE": self.project_metadata.language.value,
            "SANITIZER": sanitizer or "address",
            "FUZZING_ENGINE": fuzzing_engine or "libfuzzer",
        }
        real_env.update(extra_env or {})

        # Lastly, run the build.sh script in the container
        builder_workdir = self.get_builder_workdir()
        volumes = {
            # self.out_dir_src: '/src',
            self.artifacts_dir_work: "/work",
            self.artifacts_dir_out: "/out",
        }
        if project_source_to_mount:
            volumes[project_source_to_mount.resolve()] = builder_workdir
        if extra_files:
            for src, dst in extra_files.items():
                volumes[Path(src).resolve()] = dst


        built = self.builder_image_run(
            *(self.get_build_command(preserve_built_src_dir=preserve_built_src_dir) if not custom_build_command else custom_build_command),
            volumes=volumes,
            extra_env=real_env,
            force_local_run=True,
            print_output=print_output,
            timeout=timeout,
        )

        if mount_tmp_dir:
            shutil.rmtree(mount_tmp_dir, ignore_errors=True)

        # move the out/.shellphish_src to the src artifact
        if preserve_built_src_dir:
            # ensure the artifacts src directory was wiped
            shutil.rmtree(self.artifacts_dir / 'src', ignore_errors=True)

            # force delete it if dst exists
            dot_shellphish_dst = self.artifacts_dir_built_src / '.shellphish_src'
            if dot_shellphish_dst.exists():
                shutil.rmtree(dot_shellphish_dst, ignore_errors=True)

            shutil.move(self.artifacts_dir_out / '.shellphish_src', self.artifacts_dir_built_src)

        with open(self.artifacts_dir_out / "shellphish_build_metadata.yaml", "w") as f:
            yaml.safe_dump(
                {
                    "harnesses": self.harnesses,
                    "architecture": "x86_64",
                    "source_repo_path": str(self.get_builder_workdir()),
                    "project_name": self.project_name,
                    "sanitizer": str(sanitizer or "address"),
                    "fuzzing_engine": fuzzing_engine or "libfuzzer",
                },
                f,
            )

        return BuildTargetResult.model_validate(dict(
            build_success=built.task_success, # for local builds, the task success is the build success
            **built.model_dump(), # remove task_success from the dict
        ))

    @tracer.start_as_current_span("build_target__service")
    def build_target__service(
        self,
        patch_content: str = None,
        patch_path: Path = None,
        git_ref: str = None,
        fuzzing_engine: str = None,
        sanitizer: str = None,
        extra_env: Dict[str, str] = None,
        print_output: bool = True,
        preserve_built_src_dir: bool = False,
        extra_files: Dict[str, str] = None,
        priority: float = 2.0,
        quota: Dict[str, str] = None,
        resource_limits: Dict[str, str] = None,
        custom_build_command: List[str] = None,
        timeout: int = None,
        get_cached_build: bool = False,
    ) -> BuildTargetResult:
        if quota is None:
            quota = {
                'cpu': '6',
                'mem': '26Gi',
            }

        assert quota is not None, "Quota is required"

        assert not FORBID_SERVICE_RUN, "Service runs are forbidden"

        assert not patch_content or not patch_path, (
            "Only one of patch_content or patch_path should be provided"
        )
        if patch_path:
            with open(patch_path, "r") as f:
                patch_content = f.read()

        extra_files_b64 = {}
        if extra_files:
            for src, dst in extra_files.items():
                with open(src, "rb") as f:
                    content = f.read()
                extra_files_b64[dst] = Base64Bytes.from_bytes(content)

        if get_cached_build:
            request = ProjectBuildRequest(
                project_id=self.project_id,
                docker_image=self.get_builder_image_name(),
                project_language=self.project_metadata.language,
                sanitizer=sanitizer or 'address',
                fuzzing_engine=fuzzing_engine or 'libfuzzer',
                env=extra_env or {},
                timeout=timeout,
                command=(self.get_build_command() if not custom_build_command else custom_build_command),
                patch=base64.b64encode(patch_content.encode()).decode() if patch_content else None,
                preserve_built_src_dir=preserve_built_src_dir,
                git_ref=git_ref,
                extra_files=extra_files_b64,
                priority=priority,
                quota=quota,
                resource_limits=resource_limits,
                nonce=None
            )
        else:
            request = ProjectBuildRequest(
                project_id=self.project_id,
                docker_image=self.get_builder_image_name(),
                project_language=self.project_metadata.language,
                sanitizer=sanitizer or 'address',
                fuzzing_engine=fuzzing_engine or 'libfuzzer',
                env=extra_env or {},
                timeout=timeout,
                command=(self.get_build_command() if not custom_build_command else custom_build_command),
                patch=base64.b64encode(patch_content.encode()).decode() if patch_content else None,
                preserve_built_src_dir=preserve_built_src_dir,
                git_ref=git_ref,
                extra_files=extra_files_b64,
                priority=priority,
                quota=quota,
                resource_limits=resource_limits,
            )


        did_submit = False
        for i in range(20):
            time_submitted = datetime.now(tz=timezone.utc)
            try:
                did_submit = False
                result = request_target_build(request, self.pdclient)
                did_submit = True
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.warning(f"We tried to submit the build but for some reason it failed. We will try again to make sure it was submitted.")
                time.sleep(20)
                continue

            if not result.was_submitted():
                logger.warning(f"We tried to submit the build but for some reason it says it failed to submit. We will try again to make sure it was submitted.")
                time.sleep(20)
                continue
            break
        else:
            if not did_submit:
                raise RuntimeError("We failed to submit the build after 20 attempts")
            logger.warning("We did not get confirmation that the build was submitted. Assuming it was...")

        logger.info("Build submitted")
        result.await_completion()
        logger.info("Build completed")
        status, meta = result.get_status()
        if status == JobStatus.TIMEOUT:
            logs = result.get_logs()
            raise TimeoutError(
                "The build task timed out: " + logs.decode("utf-8", errors="replace")
            )
        elif status == JobStatus.FAILURE:
            logs = result.get_logs()
            raise RuntimeError(
                "The build task failed: " + logs.decode("utf-8", errors="replace")
            )

        assert status == JobStatus.SUCCESS, f"Unexpected status {status}"
        build_result = result.get_build_result()
        end_time: datetime = meta["end_time"]
        start_time: datetime = meta["start_time"]
        # exit_code = meta['exit_code']
        task_success = meta["success"]
        task_timeout = meta["timeout"]

        stdout = result.get_build_stdout()
        stderr = result.get_build_stderr()

        print(self.artifacts_dir)
        # result.download_build_artifacts(str(self.artifacts_dir).rstrip('/')+'.tar.gz', extract=False)
        result.download_build_artifacts_dir(self.artifacts_dir)

        with open(self.artifacts_dir_out / "shellphish_build_metadata.yaml", "w") as f:
            yaml.safe_dump(
                {
                    "harnesses": self.harnesses,
                    "architecture": "x86_64",
                    "source_repo_path": str(self.get_builder_workdir()),
                    "project_name": self.project_name,
                    "sanitizer": str(sanitizer or "address"),
                    "fuzzing_engine": str(fuzzing_engine or "libfuzzer"),
                },
                f,
            )

        return BuildTargetResult(
            task_success=task_success,
            build_success=build_result is not None and build_result.build_success,
            time_scheduled=time_submitted.timestamp(),
            time_start=start_time.timestamp(),
            time_end=end_time.timestamp(),
            time_taken=(end_time - start_time).total_seconds(),
            stdout=stdout,
            stderr=stderr,
            build_request_id=result.get_request_id(),
        )

    @tracer.start_as_current_span("build_target")
    def build_target(self, *args, **kwargs):
        if self.use_task_service:
            return self.build_target__service(*args, **kwargs)
        else:
            return self.build_target__local(*args, **kwargs)

    def get_harness_source_target_container_path__debug_symbols(
        self, harness: str
    ) -> Optional[Path]:
        harness_binary_path = self.artifacts_dir_out / harness
        harness_binary_path = Path(harness_binary_path).resolve().absolute()

        if self.project_metadata.language in [LanguageEnum.c, LanguageEnum.cpp]:
            target_func_name = FUZZ_TARGET_SEARCH_STRING
            # Use dwarfdump to locate source file for this function
            harness_absolute_source_file = locate_file_for_function_via_dwarf(
                harness_binary_path, target_func_name
            )
            if harness_absolute_source_file is None:
                return None
            return harness_absolute_source_file

        elif self.project_metadata.language in [LanguageEnum.jvm]:
            # TODO find where the jazzer source is
            return None

        else:
            assert False, f"Unsupported language {self.project_metadata.language}"


    def get_harness_function_name(self) -> str:
        return {
            LanguageEnum.c: 'LLVMFuzzerTestOneInput',
            LanguageEnum.cpp: 'LLVMFuzzerTestOneInput',
            LanguageEnum.jvm: 'fuzzerTestOneInput',
        }[self.project_metadata.language]

    def get_harness_source_target_container_path__function_index(self, harness: str, resolver: FunctionResolver) -> Optional[Path]:
        for key in resolver.find_by_funcname(self.get_harness_function_name()):
            container_path = resolver.get_target_container_path(key)
            if harness == container_path.name.split('.')[0]:
                return container_path

        # NOTE: if we are here, we did not find a single harness, let's try
        #       to recover.
        if self.project_metadata.language == LanguageEnum.jvm:
            # NOTE: the backup solution is to look for function marked as @FuzzTest
            annotated_funcs_keys = resolver.find_functions_with_annotation("@FuzzTest")
            for key in annotated_funcs_keys:
                container_path = resolver.get_target_container_path(key)
                if harness == container_path.name.split('.')[0]:
                    return container_path

        return None

    def get_harness_source_target_container_path__augmented_meta(self, harness: str, resolver: FunctionResolver) -> Optional[Path]:
        if not self.augmented_metadata:
            return None

        src_loc = self.augmented_metadata.harness_source_locations.get(harness)
        if not src_loc:
            return None

        results = resolver.resolve_source_location(src_loc)
        if not results:
            return None
        if len(results) == 1:
            logger.info(
                f"Found source location for harness {harness} in augmented metadata: {results[0]}",
                extra={
                    "harness": harness,
                    "source_location": results[0],
                }
            )
            (_, container_path) = results[0]
            return container_path

        logger.warning(
            f"Multiple source locations found for harness {harness} in augmented metadata: {results}. Using the first one."
            f" This may be a bug in the metadata or a realllllllllly weird target (*cough* jenkins *cough*)",
            extra={
                "harness": harness,
                "source_locations": results,
            }
        )
        for _, container_path in results:
            return container_path
        return None

    def get_harness_source_target_container_path(self, harness: str, resolver: FunctionResolver, use_index=True) -> Optional[Path]:
        if use_index:
            if key := self.get_harness_function_index_key(harness, resolver):
                container_path = resolver.get_target_container_path(key)
                if container_path:
                    return container_path

        if path := self.get_harness_source_target_container_path__augmented_meta(harness, resolver):
            return path
        if path := self.get_harness_source_target_container_path__debug_symbols(harness):
            return path
        elif path := self.get_harness_source_target_container_path__function_index(harness, resolver):
            return path

        if artiphishell_should_fail_on_error():
            assert False, f"Could not find source for harness {harness}!"
        return None

    def get_harness_source_artifacts_path(self, harness: str, resolver: FunctionResolver) -> Optional[Path]:
        if container_path := self.get_harness_source_target_container_path(harness, resolver):
            return self.artifacts_path(container_path=container_path)
        return None

    def get_harness_function_index_key_augmented(self, harness: str, resolver: FunctionResolver) -> Optional[FUNCTION_INDEX_KEY]:
        if not self.augmented_metadata:
            return None

        src_loc = self.augmented_metadata.harness_source_locations.get(harness)
        if not src_loc:
            return None

        results = resolver.resolve_source_location(src_loc)
        if not results:
            return None
        if len(results) == 1:
            logger.info(
                f"Found source location for harness {harness} in augmented metadata: {results[0]}",
                extra={
                    "harness": harness,
                    "source_location": results[0],
                }
            )
            (key, _rankings) = results[0]
            return key

        logger.warning(
            f"Multiple source locations found for harness {harness} in augmented metadata: {results}. Using the first one."
            f" This may be a bug in the metadata or a realllllllllly weird target (*cough* jenkins *cough*)",
            extra={
                "harness": harness,
                "source_locations": results,
            }
        )
        for key, _rankings in results:
            return key

    def get_harness_function_index_key(self, harness_name: str, resolver: FunctionResolver) -> Optional[str]:
        if key := self.get_harness_function_index_key_augmented(harness_name, resolver):
            return key
        # If we are not using augmented metadata, we need to find the function name in the container
        # and then find the key in the function index
        # This is a bit of a hack, but it works for now

        # of the augmented already failed, don't use the index to find the harness
        harness_container_path = self.get_harness_source_target_container_path(harness=harness_name, resolver=resolver, use_index=False)

        fuzztest_annotated_functions = list(resolver.find_functions_with_annotation("@FuzzTest"))
        for key in resolver.find_by_filename(harness_container_path):
            if key in fuzztest_annotated_functions or resolver.get_funcname(key) == self.get_harness_function_name():
                return key
        return None

    @property
    def harnesses(self) -> List[str]:
        """
        Returns the names of the harnesses inside the `out/` directory of the target
        """
        return [Path(p).name for p in get_fuzz_targets(self.artifacts_dir_out)]

    @tracer.start_as_current_span("fuzz_harness__local")
    def fuzz_harness__local(
        self,
        harness: str,
        sync_dir: Union[Path, str] = None,
        instance_name: str = None,
        fuzzing_engine: str = None,
        sanitizer: str = None,
        extra_docker_args: List[str] = None,
        extra_env: Dict[str, str] = None,
        skip_seed_corpus: bool = False,
        skip_dictionary: bool = False,
        use_tmp_shm: bool = True,
        *args,
        **kwargs,
    ):
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        # default_instance_name = f'{self.project_name}_{harness}_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        assert instance_name is not None, "Instance name must be provided"

        default_extra_env = {
            "RUN_FUZZER_MODE": "interactive",
            "FUZZING_ENGINE": fuzzing_engine or "libfuzzer",
            "SANITIZER": str(sanitizer) or "address",
            "ARTIPHISHELL_FUZZER_SYNC_DIR": str(sync_dir),
            "ARTIPHISHELL_FUZZER_INSTANCE_NAME": instance_name,
            "ARTIPHISHELL_PROJECT_NAME": self.project_name,
            "ARTIPHISHELL_HARNESS_NAME": harness,
        }
        if skip_seed_corpus:
            default_extra_env['SKIP_SEED_CORPUS'] = '1'
        if skip_dictionary:
            default_extra_env['SKIP_DICTIONARY'] = '1'
        default_extra_env.update(extra_env or {})

        volumes = {
            self.artifacts_dir_out: "/out",
            self.artifacts_dir_work: "/work",
            self.shared_dir: "/shared",
        }
        if use_tmp_shm:
            volumes[self.tmp_shm_dir(instance_name)] = "/tmp"

        return self.runner_image_run(
            "run_fuzzer",
            harness,
            *args,
            **kwargs,
            extra_docker_args=extra_docker_args,
            volumes=volumes,
            extra_env=default_extra_env,
            force_local_run=True,
        )

    @tracer.start_as_current_span("fuzz_harness")
    def fuzz_harness(self, *args, **kwargs):
        return self.fuzz_harness__local(*args, **kwargs)

    @tracer.start_as_current_span("run_input__local")
    def run_input__local(
        self,
        harness: str,
        *args,
        data_file=None,
        data: bytes = None,
        sanitizer: str = "address",
        extra_env: Dict[str, str] = None,
        fuzzing_engine: str = "libfuzzer",
        timeout: int = 60,
        losan: bool = False,
        **kwargs,
    ) -> RunImageResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"
        # Assert that the artifacts_dir_work exists
        assert self.artifacts_dir_work.exists(), (
            f"Artifacts directory {self.artifacts_dir_work} does not exist. You must build the project first"
        )
        assert data is None or type(data) is bytes
        assert data is None or data_file is None

        default_extra_env = {
            "RUN_FUZZER_MODE": "interactive",
            "TESTCASE": "/work/pov_input",
            "FUZZING_ENGINE": fuzzing_engine,
            "SANITIZER": str(sanitizer),
            "ARTIPHISHELL_FUZZER_INSTANCE_NAME": "run_pov",
            "ARTIPHISHELL_PROJECT_NAME": self.project_name,
            "ARTIPHISHELL_HARNESS_NAME": harness,
        }


        if(losan):
            default_extra_env["SHELL_SAN"] = "LOSAN"

        default_extra_env.update(extra_env or {})

        with tempfile.NamedTemporaryFile() as f:
            if data:
                f.write(data)
                f.seek(0)
                f.flush()
                data_file = f.name
            shutil.copy(data_file, self.artifacts_dir_work / "pov_input")
            result = self.runner_image_run(
                "reproduce",
                harness,
                *args,
                **kwargs,
                volumes={
                    self.artifacts_dir_out: "/out",
                    self.artifacts_dir_work: "/work",
                },
                extra_env=default_extra_env,
                timeout=timeout,
                force_local_run=True,
            )
            return result

    # @tracer.start_as_current_span("run_input__service")
    # def run_input__service(
    #     self,
    #     harness: str,
    #     *args,
    #     data_file=None,
    #     data: Path = None,
    #     extra_env: Dict[str, str] = None,
    #     timeout: int = 60,
    #     losan: bool = False,
    #     **kwargs,
    # ) -> RunImageResult:
    #     assert not FORBID_SERVICE_RUN, "Service runs are forbidden"

    #     assert data is None or type(data) is bytes
    #     assert data is None or data_file is None, (
    #         "Only one of data or data_file should be provided"
    #     )

    #     if data_file:
    #         with open(data_file, "rb") as f:
    #             data = f.read()

    #     default_extra_env = {
    #         "RUN_FUZZER_MODE": "interactive",
    #         "TESTCASE": "/work/pov_input",
    #         "ARTIPHISHELL_FUZZER_INSTANCE_NAME": "run_pov",
    #         "ARTIPHISHELL_PROJECT_NAME": self.project_name,
    #         "ARTIPHISHELL_HARNESS_NAME": harness,
    #     }

    #     if(losan):
    #         default_extra_env["SHELL_SAN"] = "LOSAN"

    #     default_extra_env.update(extra_env or {})

    #     request = ProjectRunTaskRequest(
    #         project_id=self.project_id,
    #         project_language=self.project_language.value,
    #         docker_image=self.get_runner_image_name(),
    #         sanitizer=kwargs.get("sanitizer", None),
    #         fuzzing_engine=kwargs.get("fuzzing_engine", None),
    #         extra_files={
    #             "/work/pov_input": Base64Bytes.from_bytes(data),
    #         },
    #         env=default_extra_env,
    #         timeout=timeout,
    #         command=["reproduce", harness, *args],
    #         volumes_id=None,
    #         collect_artifacts=True,
    #     )
    #     time_submitted = datetime.now(tz=timezone.utc)
    #     service_run = request_target_run(
    #         request,
    #         {
    #             self.artifacts_dir_out: "/out",
    #             self.artifacts_dir_work: "/work",
    #         },
    #         self.pdclient,
    #     )
    #     assert service_run.was_submitted()
    #     service_run.await_completion()
    #     status, meta = service_run.get_status()
    #     if status == JobStatus.TIMEOUT:
    #         logs = service_run.get_logs()
    #         raise TimeoutError(
    #             "The run task timed out: " + logs.decode("utf-8", errors="replace")
    #         )
    #     elif status == JobStatus.FAILURE:
    #         logs = service_run.get_logs()
    #         raise RuntimeError(
    #             "The run task failed: " + logs.decode("utf-8", errors="replace")
    #         )
    #     else:
    #         assert status == JobStatus.SUCCESS, f"Unexpected status {status}"

    #     end_time: datetime = meta["end_time"]
    #     start_time: datetime = meta["start_time"]
    #     run_result = service_run.get_run_result()
    #     run_exit_code = run_result.run_exit_code
    #     success = meta["success"]
    #     timeout = meta["timeout"]

    #     stdout = service_run.get_run_stdout()
    #     stderr = service_run.get_run_stderr()

    #     return RunImageResult(
    #         task_success=success,
    #         run_exit_code=run_exit_code,
    #         time_scheduled=time_submitted.timestamp(),
    #         time_start=start_time.timestamp(),
    #         time_end=end_time.timestamp(),
    #         time_taken=(end_time - start_time).total_seconds(),
    #         stdout=stdout,
    #         stderr=stderr,
    #     )

    @tracer.start_as_current_span("run_input")
    def run_input(self, *args, **kwargs):
        # if self.use_task_service:
        #     return self.run_input__service(*args, **kwargs)
        # else:
        return self.run_input__local(*args, **kwargs)

    @tracer.start_as_current_span("run_pov")
    def run_pov(self, harness, *args, function_resolver=None, sanitizer=None, **kwargs) -> RunPoVResult:
        result = self.run_input(harness, *args, **kwargs)
        if sanitizer is None:
            sanitizer = self.get_built_sanitizer()
        pov = parse_run_pov_result(
            self.project_metadata.language,
            sanitizer=sanitizer,
            run_pov_result=result,
            target_source_root=self.get_builder_workdir(),
            function_resolver=function_resolver,
        )
        run_pov_result = RunPoVResult(
            **result.model_dump(),
            pov=pov,
        )
        return run_pov_result

    @property
    def coverage_extra_args(self):
        """Returns project coverage extra args."""
        project_yaml_path = self.project_yaml_path
        if not os.path.exists(project_yaml_path):
            logger.warning("project.yaml not found: %s.", project_yaml_path)
            return ""

        with open(project_yaml_path) as file_handle:
            content = file_handle.read()

        coverage_flags = ""
        read_coverage_extra_args = False
        # Pass the yaml file and extract the value of the coverage_extra_args key.
        # This is naive yaml parsing and we do not handle comments at this point.
        for line in content.splitlines():
            if read_coverage_extra_args:
                # Break reading coverage args if a new yaml key is defined.
                if len(line) > 0 and line[0] != " ":
                    break
                coverage_flags += line
            if "coverage_extra_args" in line:
                read_coverage_extra_args = True
                # Include the first line only if it's not a multi-line value.
                if "coverage_extra_args: >" not in line:
                    coverage_flags += line.replace("coverage_extra_args: ", "")
        return coverage_flags

    @tracer.start_as_current_span("collect_coverage_background_start__local")
    def collect_coverage_background_start__local(
        self,
        input_dir: Path,
        harnesses: List[str] = None,
        architecture="x86_64",
        *args,
        **kwargs,
    ) -> RunImageInBackgroundResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        result = self.image_run_background__local(
            self.get_runner_image_name(),
            "coverage",
            *(harnesses if harnesses else []),
            *args,
            **kwargs,
            volumes={
                self.artifacts_dir_out: "/out",
                self.artifacts_dir_work: "/work",
                # self.out_dir_src: '/src',
                self.shared_dir: "/shared",
                input_dir: "/corpus",
            },
            extra_env={
                "FUZZING_ENGINE": "libfuzzer",
                "HELPER": "True",
                "FUZZING_LANGUAGE": self.project_metadata.language.value,
                "PROJECT": self.project_name,
                "SANITIZER": "coverage",
                "COVERAGE_EXTRA_ARGS": self.coverage_extra_args,
                "ARCHITECTURE": architecture,
            },
        )

        return result

    @tracer.start_as_current_span("collect_coverage__local")
    def collect_coverage__local(
        self,
        input_dir: Path,
        harnesses: List[str] = None,
        architecture="x86_64",
        *args,
        **kwargs,
    ) -> RunImageResult:
        assert not FORBID_LOCAL_RUN, "Local runs are forbidden"

        result = self.runner_image_run(
            "coverage",
            *(harnesses if harnesses else []),
            *args,
            **kwargs,
            volumes={
                self.artifacts_dir_out: "/out",
                self.artifacts_dir_work: "/work",
                # self.out_dir_src: '/src',
                self.shared_dir: "/shared",
                input_dir: "/corpus",
            },
            extra_env={
                "FUZZING_ENGINE": "libfuzzer",
                "HELPER": "True",
                "FUZZING_LANGUAGE": self.project_metadata.language.value,
                "PROJECT": self.project_name,
                "SANITIZER": "coverage",
                "COVERAGE_EXTRA_ARGS": self.coverage_extra_args,
                "ARCHITECTURE": architecture,
            },
            force_local_run=True,
        )

        return result

    @tracer.start_as_current_span("test_target")
    def run_tests(
        self,
        patch_path: Path = None,
        sanitizer: str = None,
        timeout: int = 60*5,
        print_output: bool = False,
        **kwargs,
    ) -> RunTestsResult:
        """
        Runs the test cases for this project, if they exist. If they do not, this will still return True, but
        log a warning and return a RunTestsResult with tests_exist=False. By default tests have timeout.
        """
        no_tests_result = RunTestsResult(tests_exist=False, all_passed=False)

        # sanity checks
        tests_script = self.project_path / self.RUN_TESTS_SCRIPT
        if not tests_script.exists():
            logger.warning(f"No tests script found at {tests_script}. This project does not support tests.")
            return no_tests_result
        if not sanitizer:
            raise ValueError("Sanitizer must be provided to run tests")

        # mount tests script and create the command to run it (taken from AIxCC specification)
        test_mnt = "/test-mnt.sh"
        inner_command = f"pushd $SRC && cp {test_mnt} $SRC/test.sh && chmod +x $SRC/test.sh && $SRC/test.sh && popd; RETCODE=$?; set -x; exit $RETCODE"
        run_tests_cmd = ["bash", "-c", inner_command]

        # build the target with the tests script mounted
        build_res = None
        had_timeout = False
        try:
            build_res = self.build_target(
                custom_build_command=run_tests_cmd,
                patch_path=patch_path,
                sanitizer=sanitizer,
                extra_files={str(tests_script): test_mnt},
                print_output=print_output,
                timeout=timeout,
            )
        except TimeoutError:
            had_timeout = True
        except Exception as e:
            logger.error("Failed to run tests due to an internal error: %s", e)
            return no_tests_result

        # XXX: local can behave differently so we set again just in case it catches the timout
        if build_res is not None:
            had_timeout |= (build_res.run_exit_code == 124)

        if had_timeout:
            logger.warning(f"Tests timed out so tests results may not be accurate.")

        logger.info(f"<<<The results of the build_res.run_exit_code is {build_res.run_exit_code}>>>")

        return RunTestsResult(
            tests_exist=True,
            # XXX: a timeout is counted as a success
            all_passed=had_timeout or build_res.build_success,
            timedout=had_timeout,
            stdout=build_res.stdout.decode('utf-8', errors='ignore'),
            stderr=build_res.stderr.decode('utf-8', errors='ignore')
        )


    def run_ossfuzz_build_check(
        self, sanitizer: str = "address", fuzzing_engine: str = "libfuzzer", extra_env: Dict[str, str] = None,
        print_output: bool = True,
    ) -> RunOssFuzzBuildCheckResult:
        """
        Runs the oss-fuzz build check command to ensure that the target can be built with the given sanitizer and fuzzing engine.
        """
        # sanity checks
        art_out_dir = Path(self.artifacts_dir_out).resolve()
        if not art_out_dir.exists() or not art_out_dir.is_dir():
            raise FileNotFoundError(f"Artifacts directory {art_out_dir} does not exist. You must build the project first")
        if len(list(art_out_dir.iterdir())) == 0:
            raise FileNotFoundError(f"Artifacts directory {art_out_dir} is empty. You must build the project first")

        # note: errored check results still count as a pass since they are assumed to be enviornment errors
        # not errors in the actual check of the target
        errored_check_result = RunOssFuzzBuildCheckResult(all_passed=True, internal_error=True)

        default_extra_env = {
            "ARCHITECTURE": "x86_64",
            "SANITIZER": sanitizer,
            "FUZZING_ENGINE": fuzzing_engine,
            "ARTIPHISHELL_PROJECT_NAME": self.project_name,
        }
        default_extra_env.update(extra_env or {})

        run_res = None
        had_timeout = False
        try:
            run_res = self.runner_image_run(
                "test_all.py",
                volumes={
                    self.artifacts_dir_work: "/work",
                    self.artifacts_dir_out: "/out",
                },
                extra_env=default_extra_env,
                force_local_run=True,
                print_output=print_output,
            )
        except TimeoutError:
            had_timeout = True
        except Exception as e:
            logger.error("Failed to run oss-fuzz build check due to an internal error: %s", e)
            return RunOssFuzzBuildCheckResult(
                all_passed=True,
                internal_error=True,
                timedout=had_timeout,
                stdout="",
                stderr=str(e),
            )

        if run_res is not None:
            had_timeout |= (run_res.run_exit_code == 124)

        #stdout = run_res.stdout.decode('utf-8', errors='ignore')
        #stderr = run_res.stderr.decode('utf-8', errors='ignore')
        #if "not found" in stdout or "not found" in stderr:
        #    logger.error("The oss-fuzz build checker was not found. The target may not be built correctly.")
        #    return errored_check_result

        return RunOssFuzzBuildCheckResult(
            all_passed=run_res.task_success or had_timeout,
            timedout=had_timeout,
            internal_error=False,
            stdout=run_res.stdout.decode('utf-8', errors='ignore'),
            stderr=run_res.stderr.decode('utf-8', errors='ignore'),
        )

class InstrumentedOssFuzzProject(OSSFuzzProject):
    def __init__(self, instrumentation, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instrumentation = instrumentation

    def get_builder_image_name(self, commit_hash=None):
        return (
            super().get_builder_image_name(commit_hash)
            + f"--{self.instrumentation.get_tool_name()}"
        )

    def get_runner_image_name(self):
        return (
            super().get_runner_image_name()
            + f"--{self.instrumentation.get_tool_name()}"
        )

    @tracer.start_as_current_span("instrumented.build_prebuild_image")
    def build_prebuild_image(self, push: bool = False):
        oss_fuzz_base_builder_image = super().oss_fuzz_base_builder_image()
        prebuild_dockerfile = self.instrumentation.get_prebuild_dockerfile(self)
        if not prebuild_dockerfile:
            return oss_fuzz_base_builder_image

        docker_context_dir = self.instrumentation.prepare_context_dir(self)
        # a prebuild image is required, so build it
        image_name = self.instrumentation.get_prebuild_image_name(self)
        assert image_name, "Prebuild image name must be retrievable if a prebuild image is used"
        image_name = super().docker_build(
            image_name,
            prebuild_dockerfile,
            docker_context_dir,
            "--build-arg",
            f"OSS_FUZZ_BASE_BUILDER_IMAGE={oss_fuzz_base_builder_image}",
            push=push,
        )
        return image_name


    @tracer.start_as_current_span("instrumented.build_builder_image")
    def build_builder_image(
        self,
        image_name: str = None,
        dockerfile: Path = None,
        context_dir: Path = None,
        push: bool = False,
    ):
        image_name = super().build_builder_image(
            image_name, dockerfile, context_dir, push=push
        )

        target_image_name = f"{image_name}--{self.instrumentation.get_tool_name()}"

        builder_dockerfile = self.instrumentation.get_builder_dockerfile(self)
        docker_context_dir = self.instrumentation.prepare_context_dir(self)

        if builder_dockerfile:
            # First try to pull the image from the registry before we attempt to build it
            if is_in_k8s():
                try:
                    self.docker_pull(target_image_name, retries=0)
                    return target_image_name
                except subprocess.CalledProcessError:
                    pass
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                logger.warning(f"📦🛠️ Image {target_image_name} not found in registry, building it")

            prebuild_image_name = self.instrumentation.get_prebuild_image_name(self)
            instrumented_image = self.docker_build(
                target_image_name,
                builder_dockerfile,
                docker_context_dir,
                "--build-arg",
                f"BASE_IMAGE={image_name}",
                "--build-arg",
                f"PREBUILD_IMAGE={prebuild_image_name}",
                push=push,
            )
        else:
            instrumented_image = self.docker_tag(
                image_name,
                target_image_name,
                push=push,
                pull=is_in_k8s() or push,
            )
        return instrumented_image

    @tracer.start_as_current_span("instrumented.build_runner_image")
    def build_runner_image(self, push: bool = False):
        runner_image_name = self.get_runner_image_name()

        # First try to pull the image from the registry before we attempt to build it
        if is_in_k8s():
            try:
                self.docker_pull(runner_image_name, retries=0)
                return runner_image_name
            except subprocess.CalledProcessError:
                pass
            except Exception as e:
                import traceback
                traceback.print_exc()
            logger.warning(f"📦🛠️ Image {runner_image_name} not found in registry, building it")

        runner_docker = self.instrumentation.get_runner_dockerfile(self)
        base_runner_image = super().build_runner_image(push=push)
        assert runner_image_name == f"{base_runner_image}--{self.instrumentation.get_tool_name()}"


        if not runner_docker:
            return self.docker_tag(
                base_runner_image,
                runner_image_name,
                push=push,
                pull=is_in_k8s() or push,
            )

        prebuild_image_name = self.instrumentation.get_prebuild_image_name(self)
        return self.docker_build(
            runner_image_name,
            runner_docker,
            self.instrumentation.prepare_context_dir(self),
            "--build-arg",
            f"BASE_IMAGE={self.get_base_runner_image_name()}",
            "--build-arg",
            f"PREBUILD_IMAGE={prebuild_image_name}",
            push=push,
        )

    @tracer.start_as_current_span("instrumented.build_target")
    def build_target(
        self, sanitizer: str = None, extra_env: Dict[str, str] = None, *args, **kwargs
    ):
        # Catching some badness to save people debugging time :)
        if sanitizer == 'coverage' and self.instrumentation.get_tool_name() != 'coverage_fast':
            assert False, "Coverage sanitizer must be used with the 'coverage_fast' instrumentation"
        if self.instrumentation.get_tool_name() == 'coverage_fast' and sanitizer != 'coverage':
            assert False, "The 'coverage_fast' instrumentation must be used with the 'coverage' sanitizer"

        extra_env = extra_env or {}

        result = super().build_target(
            fuzzing_engine=self.instrumentation.get_fuzzing_engine_name(),
            sanitizer=sanitizer,
            extra_env=extra_env,
            *args,
            **kwargs,
        )
        self.instrumentation.post_build(self)
        return result

    @tracer.start_as_current_span("instrumented.fuzz_harness__local")
    def fuzz_harness__local(
        self,
        harness: str,
        instance_name: str = None,
        fuzzing_engine: str = None,
        sanitizer: str = None,
        *args,
        **kwargs,
    ):
        return super().fuzz_harness__local(
            harness,
            instance_name=instance_name,
            fuzzing_engine=fuzzing_engine
            or self.instrumentation.get_fuzzing_engine_name(),
            sanitizer=sanitizer or "address",
            *args,
            **kwargs,
        )


if __name__ == "__main__":
    import sys

    oss_fuzz_path = Path(sys.argv[1]).resolve().absolute()

    project_dirs = list((oss_fuzz_path / "projects").iterdir())
    for i, project_path in enumerate(project_dirs):
        print(f"{i}/{len(project_dirs)}: Checking {project_path}")
        if not (project_path / "Dockerfile").is_file():
            continue

        proj = OSSFuzzProject(project_path)
        # proj.build_builder_image(proj.get_builder_image_name())
        # proj.docker_extract_sources(Path('/tmp/src'), Path('/tmp/work'), Path('/tmp/out'))

        build_afl_shellphish(proj)
        print(proj.artifacts_out_path)
        # build_afl_shellphish(proj)
        build_jazzer_shellphish(proj)
        # print(proj.out_path)

        # break

        # project = OSSFuzzProject(project_path)
        # assert project.dockerfile_path.exists()
        # assert project.project_metadata.language in ['c', 'c++', 'go', 'rust', 'python', 'jvm', 'swift', 'javascript', 'ruby']


class OssFuzzProject:
    pass
