import os
from pathlib import Path
import shutil

from shellphish_crs_utils import C_INSTRUMENTATION_DIR
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.instrumentation import (
    Instrumentation,
    supported_instrumentation,
)
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))


@supported_instrumentation
class AIJONInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "shellphish_aijon"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        shutil.copy(
            str(C_INSTRUMENTATION_DIR / "anti-wrap-ld.sh"), str(INSTRUMENTATION_DIR)
        )
        shutil.copy(
            str(C_INSTRUMENTATION_DIR / "generic_harness.c"), str(INSTRUMENTATION_DIR)
        )
        shutil.copy(shutil.which("yq"), str(INSTRUMENTATION_DIR))

        return INSTRUMENTATION_DIR

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        if oss_fuzz_project.project_metadata.language in [
            LanguageEnum.c,
            LanguageEnum.cpp,
        ]:
            return INSTRUMENTATION_DIR / "Dockerfile.c.builder"
        else:
            return None

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        if oss_fuzz_project.project_metadata.language in [
            LanguageEnum.c,
            LanguageEnum.cpp,
        ]:
            return INSTRUMENTATION_DIR / "Dockerfile.c.runner"
        else:
            return None
