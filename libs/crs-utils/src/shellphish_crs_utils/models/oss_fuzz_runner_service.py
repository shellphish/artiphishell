import base64
from configparser import ConfigParser
from enum import Enum
import hashlib
from typing import Callable, Iterator, List, Optional, Any, Tuple, Dict, Annotated, Union
from pathlib import Path
import uuid

from pydantic import BaseModel, ConfigDict, field_validator, Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from typing import List, Optional

from shellphish_crs_utils.models.constraints import PDT_ID
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum, SanitizerEnum
# from shellphish_crs_utils.pydatatask import PDClient

class Base64Bytes(BaseModel):
    model_config = ConfigDict(extra="forbid", json_encoders={bytes: lambda v: base64.b64encode(v).decode()})
    content: bytes

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls.model_validate({"content": content})

    @field_validator("content", mode="before")
    def decode_base64(cls, value):
        if isinstance(value, str):
            return base64.b64decode(value)
        return value


class ProjectTaskRequest(ShellphishBaseModel):
    """
    This model is used to request oss-fuzz container tasks in the current cluster
    """

    # request_id: PDT_ID = Field(default_factory=lambda: str(uuid.uuid4().replace('-', '')))
    # """
    # Unique identifier for the task request. Can be used later to retrive artifacts or trigger a run with the build results
    # """
    def compute_request_id(self) -> PDT_ID:
        jsonned = self.model_dump_json()
        return hashlib.sha256(jsonned.encode()).hexdigest()[:32] + "11"

    project_id: PDT_ID
    """
    The project id must be provided and match the project id in pdt repos
    """

    docker_image: str
    """
    The docker image should be the target image for the given oss project.
    It may be a custom image which builds on top of the target oss-fuzz image.

    If the image is in a registry, the registry should be included.

    If in k8, the registry is given via the env `DOCKER_IMAGE_PREFIX` ie `foo.com/`
    If running in local docker daemon, no registry is needed
    """
    
    quota: dict[str, Union[str, str]] = Field(default_factory=lambda: {
        'cpu': '6',
        'mem': '26Gi',
    })
    """
    The quota to use for the task, should be a dict either with:
    - `max`: a float % of total resources available to the cluster
    - `cpu` and `mem`: Explicit values for cpu and memory. Memory expects units of Gi
    """

    resource_limits: Optional[dict[str, Union[str, str]]] = Field(default_factory=lambda: {
        'cpu': '10',
        'mem': '40Gi',
    })
    """
    The resource limits to use for the task, should be a dict either with:
    - `cpu` and `mem`: Explicit values for cpu and memory. Memory expects units of Gi
    """

    priority: Union[float, str] = 2.0
    """
    The pipeline priority of the task, defaults to 2.0. Higher priorites are scheduled first.
    """

    project_language: str
    """
    The language of the project
    """

    sanitizer: SanitizerEnum = 'address'
    fuzzing_engine: str = 'libfuzzer'

    extra_files: Optional[Dict[str, Base64Bytes]] = None
    """
    Extra files to upload to the container
    """

    env: Dict[str, str] = Field(default_factory=dict)
    """
    Extra environment variables to set in the container during the build
    """

    timeout: Optional[int] = None

    command: List[str]
    """
    The command to run in the container
    """

    nonce: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    """
    Use to allow re-running the same request multiple times.
    Set to None if you want to only get cached results (including failures)
    """

class ProjectBuildRequest(ProjectTaskRequest):
    """
    Used to run a build task in the current cluster
    """

    patch: Optional[str] = None
    """
    A patch to apply to the project source code before building
    """

    command: List[str] = ['compile']
    """
    The command to run in the container, defaults to the oss-fuzz compile command
    """

    preserve_built_src_dir: Optional[bool] = False
    """
    Whether or not the built source directory should be be preserved as part of the artifacts in /out/src/
    """

    git_ref: Optional[str] = None
    """
    The git ref to checkout before building
    """

class ProjectBuildResult(ShellphishBaseModel):
    """
    The result of a build task
    """
    request_id: PDT_ID
    project_id: PDT_ID
    sanitizer: SanitizerEnum
    fuzzing_engine: str
    language: LanguageEnum
    build_success: bool

class ProjectRunTaskRequest(ProjectTaskRequest):
    """
    Used to run a run task in the current cluster
    """

    command: List[str]
    """
    Arbitrary command to run in the container
    """

    volumes_id: Optional[PDT_ID]
    """
    The ID of the volumes to mount for this task. These should be uploaded to the pdt repo `oss_fuzz_project_run.project_volumes`
    """

    collect_artifacts: Optional[bool] = False
    """
    If true, the output artifacts will be collected from the container and matched against the glob pattern provided in `output_artifacts_glob`
    """

    output_artifacts_globs: Optional[List[str]] = None
    """
    If provided, the output artifacts will be collected from the container and matched against this glob pattern
    """


class ProjectRunTaskResult(ShellphishBaseModel):
    """
    The result of a run task
    """
    run_success: bool
    run_exit_code: int

    request_id: PDT_ID
    project_id: PDT_ID
    input_volumes_id: PDT_ID