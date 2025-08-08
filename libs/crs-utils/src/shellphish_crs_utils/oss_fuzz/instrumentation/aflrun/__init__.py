import os
from pathlib import Path
import shutil

from shellphish_crs_utils import C_INSTRUMENTATION_DIR
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))

@supported_instrumentation
class AFLRunInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "aflrun"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        # shutil.copy(str(C_INSTRUMENTATION_DIR / "anti-wrap-ld.sh"), str(INSTRUMENTATION_DIR))
        # shutil.copy(str(C_INSTRUMENTATION_DIR / "generic_harness.c"), str(INSTRUMENTATION_DIR))
        shutil.copy(shutil.which("yq"), str(INSTRUMENTATION_DIR))
        return INSTRUMENTATION_DIR

    def get_prebuild_dockerfile(self, oss_fuzz_project):
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.builder"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.runner"
