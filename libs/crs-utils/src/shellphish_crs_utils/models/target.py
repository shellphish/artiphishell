from pydantic import conlist, field_validator, ValidationInfo, Field, AnyHttpUrl, AnyUrl, UUID4
from typing import Annotated, List, Dict, Optional, TypeAlias
from pathlib import Path

from shellphish_crs_utils.models.base import ShellphishBaseModel

from shellphish_crs_utils.models.constraints import PDT_ID, ID_CONSTRAINTS
from shellphish_crs_utils.models.oss_fuzz import ArchitectureEnum, SanitizerEnum

VALID_SOURCE_FILE_SUFFIXES_C = [
    ".c", ".cpp", ".cc", ".cxx", ".c++",
    ".h", ".hpp", ".hh", ".hxx", ".h++",
    ".inl",
]
VALID_SOURCE_FILE_SUFFIXES_JVM = [
    '.java',
    #'.kt', '.scala',
    #'.groovy', '.clj', '.cljs', '.cljc', '.edn',
]
VALID_SOURCE_FILE_SUFFIXES = VALID_SOURCE_FILE_SUFFIXES_C + VALID_SOURCE_FILE_SUFFIXES_JVM

class ProjectInfoMixin:
    project_id: PDT_ID = Field(description="The pydatatask target id")
    project_name: str = Field(description="The oss fuzz project name")

    @property
    def project_info(self):
        return {
            'project_id': self.project_id,
            'project_name': self.project_name,
        }

class BuildInfoMixin:
    sanitizer: SanitizerEnum = Field(description="The sanitizer used in this target configuration")
    architecture: ArchitectureEnum = Field(description="The architecture for this target configuration")

    @property
    def build_info(self):
        return {
            'sanitizer': self.sanitizer,
            'architecture': self.architecture,
        }

class HarnessInfoMixin:
    cp_harness_name: str = Field(description="The challenge project harness name")
    cp_harness_binary_path: Path = Field(description="The challenge project harness binary path")
    entrypoint_function: Optional[str] = Field(description="The entrypoint function of the harness", default=None)
    source_entrypoint: Optional[Path] = Field(description="The source file which contains the entrypoint of the harness", default=None)

    @property
    def harness_info(self):
        result = {
            'cp_harness_name': self.cp_harness_name,
            'cp_harness_binary_path': self.cp_harness_binary_path,
        }
        if self.entrypoint_function:
            result['entrypoint_function'] = self.entrypoint_function
        if self.source_entrypoint:
            result['source_entrypoint'] = self.source_entrypoint
        return result

class ProjectHarnessMetadata(ShellphishBaseModel, ProjectInfoMixin, HarnessInfoMixin):
    pass

class BuildConfiguration(ShellphishBaseModel, ProjectInfoMixin, BuildInfoMixin):
    pass

class HarnessInfo(ShellphishBaseModel, ProjectInfoMixin, BuildInfoMixin, HarnessInfoMixin):
    build_configuration_id: PDT_ID = Field(description="The pydatatask build configuration id")
    project_harness_metadata_id: Optional[PDT_ID] = Field(default=None, description="The pydatatask project harness metadata id")

class CrashingInputMetadata(HarnessInfo):
    harness_info_id: PDT_ID = Field(description="The pydatatask harness info id")
    fuzzer: str = Field(description="The fuzzer used to generate the crashing input")
    generated_by_sarif: Optional[str]= Field(
        description="The SARIF file used to generate the crashing input", default=None
    )

HARNESS_NAME: TypeAlias = str
PROJECT_NAME: TypeAlias = str