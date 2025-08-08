from configparser import ConfigParser
from enum import Enum
from typing import List, Optional, Any, Tuple, Dict, Annotated, Union
from pathlib import Path

from pydantic import field_validator, Field, HttpUrl
from shellphish_crs_utils.models.base import ShellphishBaseModel
from typing import List, Optional

from shellphish_crs_utils.models.symbols import SourceLocation

class LanguageEnum(str, Enum):
    c = "c"
    cpp = "c++"
    go = "go"
    rust = "rust"
    python = "python"
    jvm = "jvm"
    swift = "swift"
    javascript = "javascript"
    ruby = "ruby"


class SanitizerEnum(str, Enum):
    address = "address"
    memory = "memory"
    undefined = "undefined"
    thread = "thread"
    coverage = "coverage"
    none = "none"

class SanitizerConfig(ShellphishBaseModel):
    experimental: Optional[bool] = False

SanitizerWithConfig = Dict[SanitizerEnum, SanitizerConfig]


class ArchitectureEnum(str, Enum):
    x86_64 = "x86_64"
    i386 = "i386"
    aarch64 = "aarch64"


class FuzzingEngineEnum(str, Enum):
    none = "none"
    libfuzzer = "libfuzzer"
    afl = "afl"
    honggfuzz = "honggfuzz"
    centipede = "centipede"
    wycheproof = "wycheproof"

class ViewRestrictionsEnum(str, Enum):
    none = "none"

class OSSFuzzProjectYAML(ShellphishBaseModel):
    language: LanguageEnum
    homepage: Optional[str] = None
    primary_contact: Optional[str] = None # EmailStr
    auto_ccs: Optional[Union[str, List[str]]] = None # EmailStr
    main_repo: Optional[str] = None # TODO: bring Url back, but has to handle git@github.com:asdf urls
    vendor_ccs: Optional[List[str]] = None # EmailStr
    sanitizers: Optional[List[Union[SanitizerEnum, SanitizerWithConfig]]] = Field(default=['address', 'undefined'], description='Sanitizers the project supports, can opt-in to memory sanitizer or opt out of either ubsan or asan.')
    architectures: Optional[List[ArchitectureEnum]] = Field(default=['x86_64'], description='Architectures the project supports, can opt-in to i386 or aarch64.')
    fuzzing_engines: Optional[List[FuzzingEngineEnum]] = Field(default=['libfuzzer', 'afl', 'honggfuzz', 'centipede'], description='Fuzzing engines the project supports, can opt-in to afl or honggfuzz.')
    help_url: Optional[HttpUrl] = None
    builds_per_day: Optional[int] = None
    file_github_issue: Optional[bool] = None
    coverage_extra_args: Optional[str] = None
    disabled: Optional[bool] = False
    blackbox: Optional[bool] = False

    run_tests: Optional[bool] = True

    view_restrictions: Optional[ViewRestrictionsEnum] = None

    labels: Dict[str, Any] = Field(default_factory=dict)

    # allegedly this is a thing, used by bitcoin-core
    selective_unpack: Optional[bool] = False  # Required to avoid out-of-space when executing AFL on clusterfuzz bots

    shellphish_docker_image: Optional[str] = None
    shellphish_project_name: Optional[str] = None

    @field_validator('builds_per_day')
    @classmethod
    def check_builds_per_day(cls, v):
        if v is not None and (v < 1 or v > 4):
            raise ValueError('builds_per_day must be between 1 and 4')
        return v

    def is_prebuilt(self) -> bool:
        return self.shellphish_docker_image is not None

    def get_docker_image_name(self, project_name: str) -> str:
        return self.shellphish_docker_image or f"oss-fuzz-{project_name}"

    def get_project_name(self) -> str:
        if self.shellphish_project_name:
            return self.shellphish_project_name
        else:
            assert False, "Project name must be set in the shellphish_project_name field or derived from the project directory name."

class ShellphishMetadata(ShellphishBaseModel):
    fuzzing_engine: FuzzingEngineEnum
    project_name: str
    sanitizer: SanitizerEnum
    source_repo_path: str
    architecture: ArchitectureEnum
    harnesses: List[str] = Field(default_factory=list)
    harness_source_locations: Dict[str, SourceLocation] = Field(default_factory=dict)
    known_sources: Dict[str, Any] = Field(default_factory=dict, help='A mapping of known target sources to their contents')
    files_by_type: Dict[str, int] = Field(default_factory=dict, help='A mapping of known file types to the count of them in the source repo')

class AugmentedProjectMetadata(OSSFuzzProjectYAML):
    shellphish: ShellphishMetadata = Field(default_factory=dict)

    @property
    def harnesses(self) -> List[str]:
        return self.shellphish.harnesses

    @property
    def harness_source_locations(self) -> Dict[str, SourceLocation]:
        return self.shellphish.harness_source_locations

    @property
    def source_repo_path(self) -> Path:
        return Path(self.shellphish.source_repo_path)

class HarnessOptions(ShellphishBaseModel):
    libfuzzer: Optional[List[Tuple[str, str]]] = None
    afl: Optional[List[Tuple[str, str]]] = None
    honggfuzz: Optional[List[Tuple[str, str]]] = None
    centipede: Optional[List[Tuple[str, str]]] = None
    wycheproof: Optional[List[Tuple[str, str]]] = None
    none: Optional[List[Tuple[str, str]]] = None

class Harness(ShellphishBaseModel):
    name: str
    dict_path: Optional[Path] = None
    options: Optional[HarnessOptions] = None
    seed_corpus_tar_path: Optional[Path] = None

    @staticmethod
    def from_project(project_dir: Path, harness_name: str) -> 'Harness':
        harness = Harness(name=harness_name)
        options_path = project_dir / 'out' / f'{harness_name}.options'
        if options_path.exists():
            harness.options = HarnessOptions.model_validate(ConfigParser().parse(options_path))
