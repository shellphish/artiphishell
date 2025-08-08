import os
from pathlib import Path
import shutil
from typing import Optional
from shellphish_crs_utils import ARTIPHISHELL_DIR, LIBS_DIR, C_INSTRUMENTATION_DIR
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from subprocess import check_call

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))

@supported_instrumentation
class DiscoveryInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "discovery_guy"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.runner"
    
    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"