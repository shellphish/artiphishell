import os
from pathlib import Path
import shutil
from typing import Optional

from shellphish_crs_utils import C_INSTRUMENTATION_DIR
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))

@supported_instrumentation
class CodeQLInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "shellphish_codeql"

    def _internal_tool_replacement_alias(self) -> Optional[str]:
        return 'libfuzzer'

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR

    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.builder"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None