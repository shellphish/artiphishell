import hashlib
from io import BytesIO
import logging
from os import PathLike
import os
from pathlib import Path
import tarfile
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union
from shellphish_crs_utils.pydatatask import PDClient
from shellphish_crs_utils.pydatatask.client import JobStatus
from shellphish_crs_utils.models.oss_fuzz_runner_service import ProjectBuildRequest, ProjectBuildResult, ProjectRunTaskRequest, ProjectRunTaskResult
import yaml

OSS_FUZZ_PROJECT_BUILD_TASK = 'oss_fuzz_project_build'
BUILD_REQUEST_REPO = 'build_request'
BUILD_METADATA_REPO = 'project_build_metadata'
BUILD_STDOUT_REPO = 'project_build_log_stdout'
BUILD_STDERR_REPO = 'project_build_log_stderr'
BUILD_ARTIFACTS_REPO = 'project_build_artifacts'

OSS_FUZZ_RUN_TASK = 'oss_fuzz_project_run'
RUN_REQUEST_REPO = 'run_request'
RUN_METADATA_REPO = 'project_run_metadata'
RUN_STDOUT_REPO = 'project_run_log_stdout'
RUN_STDERR_REPO = 'project_run_log_stderr'
RUN_VOLUMES_REPO = 'project_volumes'
# BUILD_REQUEST_REPO = 'build_request'
# BUILD_RESULT_META_REPO = 'build_result_meta'
# BUILD_RESULT_ARTIFACTS_REPO = 'build_result_artifacts'

class PDBackedObject:
    """
    Represents the base class for a run result.
    """
    __client: PDClient

class BuildServiceRequest(PDBackedObject, ProjectBuildRequest):
    """
    Represents a requested build.
    """

    def __init__(self, client: PDClient, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client = client
        self.__cached_status = None
        self.__cached_build_result = None
        self.__cached_build_stdout = None
        self.__cached_build_stderr = None

    @property
    def __request_id(self) -> str:
        return self.compute_request_id()
    
    def get_request_id(self) -> str:
        """
        Get the request id for the build.
        public method for backwards compatibility
        """
        return self.compute_request_id()


    def was_submitted(self) -> bool:
        """
        Check if the build was submitted.
        """
        return self.__client.has_key(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_REQUEST_REPO, self.__request_id)

    def submit(self) -> str:
        """
        Submit the build request. Returns the job string.
        """
        return self.__client.post_data(
            OSS_FUZZ_PROJECT_BUILD_TASK,
            BUILD_REQUEST_REPO,
            self.compute_request_id(),
            self.model_dump_json().encode()
        )

    def get_logs(self, allow_missing: bool = False) -> Optional[bytes]:
        """
        Get the logs for the run.
        """
        return self.__client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, 'logs', self.__request_id, allow_missing=allow_missing)

    def get_build_stdout(self) -> Optional[bytes]:
        """
        Get the stdout for the build.
        """
        if not self.finished():
            return None
        if self.__cached_build_stdout is None:
            self.__cached_build_stdout = self.__client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_STDOUT_REPO, self.__request_id)
        return self.__cached_build_stdout

    def get_build_stderr(self) -> Optional[bytes]:
        """
        Get the stderr for the build.
        """
        if not self.finished():
            return None
        if self.__cached_build_stderr is None:
            self.__cached_build_stderr = self.__client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_STDERR_REPO, self.__request_id)
        return self.__cached_build_stderr

    def get_build_result(self) -> Optional[ProjectBuildResult]:
        """
        Get the metadata for the build.
        """
        if not self.finished():
            return None
        if self.__cached_build_result is None:
            result = self.__client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_METADATA_REPO, self.__request_id)
            self.__cached_build_result = ProjectBuildResult.model_validate(yaml.safe_load(result))
        return self.__cached_build_result

    def get_status(self) -> Tuple[JobStatus, Dict[str, Any]]:
        """
        Get the status for the run.
        """
        if self.__cached_status is not None:
            return self.__cached_status
        for i in range(10):
            try:
                status, meta = self.__client.query_job_status(OSS_FUZZ_PROJECT_BUILD_TASK, self.__request_id)
                logger.info("Build status: %s", status)
                if status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT):
                    self.__cached_status = (status, meta)
                return status, meta
            except Exception as e:
                logger.error("Error getting build status, trying again in 20 seconds: %s", e)
                time.sleep(20)
        raise Exception("Failed to get build status")


    def await_completion(self, timeout:int = None) -> Optional[JobStatus]:
        """
        Wait for the build to complete.
        """
        start_time = time.time()
        while timeout is None or time.time() - start_time < timeout:
            try:
                status, meta = self.get_status()
                logger.info("Build status: %s", status)
                if status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT):
                    return status
            except Exception as e:
                logger.error("Error getting build status, trying again in 20 seconds: %s", e)
                time.sleep(15)
            time.sleep(5)
        # in case of timeout just return None
        return None

    def finished(self) -> bool:
        """
        Check if the build finished.
        """
        status, meta = self.get_status()
        return status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT)

    def task_failed(self) -> bool:
        """
        Check if the build failed.
        """
        status, meta = self.get_status()
        return status == JobStatus.FAILURE

    def build_failed(self) -> bool:
        build_result = self.get_build_result()
        return build_result is not None and not build_result.build_success

    def succeeded(self) -> bool:
        """
        Check if the build succeeded.
        """
        status, meta = self.get_status()
        return status == JobStatus.SUCCESS

    def timed_out(self) -> bool:
        """
        Check if the build timed out.
        """
        status, meta = self.get_status()
        return status == JobStatus.TIMEOUT
    
    @staticmethod
    def keyed_download_build_artifacts_tar(client: PDClient, request_id: str, out_file_path: Path):
        """
        Download the artifacts as a tarball.
        """
        for i in range(10):
            try:
                return client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_ARTIFACTS_REPO, request_id, out_file_path=out_file_path)
            except Exception as e:
                logger.error("Error downloading build artifacts, trying again in 20 seconds: %s", e)
                time.sleep(20)
        raise Exception("Failed to download build artifacts")

    def download_build_artifacts_tar(self, out_file_path: str = None) -> bytes:
        """
        Download the artifacts as a tarball.
        """
        for i in range(10):
            try:
                return self.__client.get_data(OSS_FUZZ_PROJECT_BUILD_TASK, BUILD_ARTIFACTS_REPO, self.__request_id, out_file_path=out_file_path)
            except Exception as e:
                logger.error("Error downloading build artifacts, trying again in 20 seconds: %s", e)
                time.sleep(20)
        raise Exception("Failed to download build artifacts")

    def download_build_artifacts_dir(self, out_dir_path: Union[str, Path]) -> None:
        """
        Download the build artifacts directory and extract it to `out_dir_path`.
        """
        with tempfile.NamedTemporaryFile() as temp_tar:
            # import ipdb; ipdb.set_trace()
            temp_tar_path = Path(temp_tar.name)
            self.download_build_artifacts_tar(out_file_path=temp_tar_path)
            # then extract the tar gz
            with tarfile.open(temp_tar_path, 'r:*') as tar:
                tar.extractall(out_dir_path)

class RunServiceRequest(PDBackedObject, ProjectRunTaskRequest):
    """
    Represents a requested run.
    """

    def __init__(self, client: PDClient, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client = client
        self.__cached_status = None

    @property
    def __request_id(self) -> str:
        return self.compute_request_id()

    def was_submitted(self) -> bool:
        """
        Check if the run was submitted.
        """
        return self.__client.has_key(OSS_FUZZ_RUN_TASK, RUN_REQUEST_REPO, self.__request_id)

    def submit(self) -> str:
        """
        Submit the run request. Returns the job string.
        """
        return self.__client.post_data(
            OSS_FUZZ_RUN_TASK,
            RUN_REQUEST_REPO,
            self.__request_id,
            self.to_json().encode()
        )

    def get_logs(self, allow_missing: bool = False) -> Optional[bytes]:
        """
        Get the logs for the run.
        """
        return self.__client.get_data(OSS_FUZZ_RUN_TASK, 'logs', self.__request_id, allow_missing=allow_missing)

    def get_run_stdout(self) -> Optional[bytes]:
        """
        Get the stdout for the run.
        """
        assert self.finished()

        return self.__client.get_data(OSS_FUZZ_RUN_TASK, RUN_STDOUT_REPO, self.__request_id)

    def get_run_stderr(self) -> Optional[bytes]:
        """
        Get the stderr for the run.
        """
        assert self.finished()

        return self.__client.get_data(OSS_FUZZ_RUN_TASK, RUN_STDERR_REPO, self.__request_id)

    def get_run_result(self) -> Optional[ProjectRunTaskResult]:
        """
        Get the metadata for the run
        """
        if not self.finished():
            return None

        result = self.__client.get_data(OSS_FUZZ_RUN_TASK, RUN_METADATA_REPO, self.__request_id)
        self.__cached_run_result = ProjectRunTaskResult.model_validate(yaml.safe_load(result))
        return self.__cached_run_result

    def get_status(self) -> Tuple[JobStatus, Dict[str, Any]]:
        """
        Get the status for the run.
        """
        if self.__cached_status is not None:
            return self.__cached_status
        status, meta = self.__client.query_job_status(OSS_FUZZ_RUN_TASK, self.__request_id)
        logger.info("Run status: %s", status)
        if status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT):
            self.__cached_status = (status, meta)
        return status, meta

    def await_completion(self, timeout:int = None) -> Optional[JobStatus]:
        """
        Wait for the run to complete.
        """
        start_time = time.time()
        while timeout is None or time.time() - start_time < timeout:
            status, meta = self.get_status()
            logger.info("Run status: %s", status)
            if status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT):
                return status
            time.sleep(5)
        # in case of timeout just return None
        return None

    def finished(self) -> bool:
        """
        Check if the run finished.
        """
        status, meta = self.get_status()
        return status in (JobStatus.SUCCESS, JobStatus.FAILURE, JobStatus.TIMEOUT)

    def failed(self) -> bool:
        """
        Check if the run failed.
        """
        status, meta = self.get_status()
        return status == JobStatus.FAILURE

    def succeeded(self) -> bool:
        """
        Check if the run succeeded.
        """
        status, meta = self.get_status()
        return status == JobStatus.SUCCESS

    def timed_out(self) -> bool:
        """
        Check if the run timed out.
        """
        status, meta = self.get_status()
        return status == JobStatus.TIMEOUT

    def download_artifacts_tar(self) -> bytes:
        """
        Download the artifacts as a tarball.
        """
        return self.__client.get_data(OSS_FUZZ_RUN_TASK, OSS_FUZZ_RUN_BUILD_ARTIFACTS_REPO, self.__request_id)

    def download_artifacts(self, out_path: Union[str, Path], extract: bool=True) -> None:
        """
        Download the build artifacts.
        """
        path = Path(out_path)
        assert (not extract and not os.path.exists(path)) or (extract and os.path.isdir(path))

        artifacts_tar = self.download_artifacts_tar()
        if extract:
            with tarfile.open(fileobj=BytesIO(artifacts_tar), mode='r:gz') as tar:
                tar.extractall(path)
        else:
            with path.open('wb') as f:
                f.write(artifacts_tar)

logger = logging.getLogger(__name__)

def request_target_build(build_request: ProjectBuildRequest, pdclient: PDClient=None) -> BuildServiceRequest:
    """
    Request a build for a given project.

    :param build_request: The build request to use for the build.
    :return: The build request that was used for the build.
    """
    if not pdclient:
        pdclient = PDClient.from_env()
    build_service_request = BuildServiceRequest(pdclient, **build_request.model_dump())

    build_request_data = build_service_request.model_dump_json().encode()
    build_request_key = build_service_request.compute_request_id()

    job = build_service_request.submit()
    assert job is not None and job == build_request_key
    logger.warning(f"Submitted job {job} for build {build_request.project_id}.")

    return build_service_request

def request_target_run(run_request: ProjectRunTaskRequest, volumes: Dict[str, Path], pdclient: PDClient=None) -> RunServiceRequest:
    """
    Request a run for a given project.

    :param run_request: The run request to use for the run.
    :return: The run request that was used for the run.
    """
    if not pdclient:
        pdclient = PDClient.from_env()

    tar_out_bytes_io = BytesIO()
    with tarfile.open(fileobj=tar_out_bytes_io, mode='w') as tar:
        for host_path, container_path in volumes.items():
            tar.add(host_path, arcname=container_path)

    tar_out_bytes = tar_out_bytes_io.getvalue()
    volumes_key = hashlib.sha256(tar_out_bytes).hexdigest()
    volumes_key_returned = pdclient.post_data(OSS_FUZZ_RUN_TASK, RUN_VOLUMES_REPO, volumes_key, tar_out_bytes)
    assert volumes_key == volumes_key_returned

    run_service_request = RunServiceRequest(pdclient, **run_request.model_dump())
    run_service_request.volumes_id = volumes_key

    run_request_data = run_service_request.model_dump_json().encode()
    run_request_key = run_service_request.compute_request_id()

    job = pdclient.post_data(
        OSS_FUZZ_RUN_TASK,
        RUN_REQUEST_REPO,
        run_request_key,
        run_request_data
    )
    assert job is not None and job == run_request_key
    logger.warning(f"Submitted job {job} for run {run_request.project_id}.")

    return run_service_request