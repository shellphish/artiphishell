import os
from pathlib import Path
import shutil
from typing import ClassVar, Optional, TypeAlias
from shellphish_crs_utils import LIBS_DIR, ARTIPHISHELL_DIR
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from subprocess import check_call

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))


@supported_instrumentation
class JazzerInstrumentation(Instrumentation):

    def get_tool_name(self) -> str:
        return "shellphish_jazzer"

    def _internal_tool_replacement_alias(self) -> Optional[str]:
        return 'libfuzzer'

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        check_call(["rsync", "-ra", "--delete", str(LIBS_DIR / "libcodeql") + "/", str(INSTRUMENTATION_DIR / "libcodeql") + "/"])
        check_call(["rsync", "-ra", "--exclude=instrumentation", "--delete", str(LIBS_DIR / "crs-utils") + "/", str(INSTRUMENTATION_DIR / "crs-utils") + "/"])
        check_call(["rsync", "-ra", "--delete", str(LIBS_DIR / "nautilus") + "/", str(INSTRUMENTATION_DIR / "nautilus") + "/"])

        return INSTRUMENTATION_DIR
    
    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.builder"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.runner"
