import os
import shutil
from pathlib import Path
from typing import Optional

from shellphish_crs_utils import LIBS_DIR
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.instrumentation import (
    Instrumentation,
    supported_instrumentation,
)
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))


@supported_instrumentation
class DyvaInstrumentation(Instrumentation):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_tool_name(self) -> str:
        return "shellphish_dyva"

    def _internal_tool_replacement_alias(self) -> Optional[str]:
        return "libfuzzer"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        shutil.copytree(str(LIBS_DIR / 'debug-lib/debug_lib/plugins/pyjdb'),
                        str(INSTRUMENTATION_DIR / 'pyjdb'),
                        dirs_exist_ok=True
                        )
        return INSTRUMENTATION_DIR

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        if oss_fuzz_project.project_metadata.language in [
            LanguageEnum.c,
            LanguageEnum.cpp,
        ]:
            return INSTRUMENTATION_DIR / "Dockerfile.c.builder"
        elif oss_fuzz_project.project_metadata.language == LanguageEnum.jvm:
            return INSTRUMENTATION_DIR / "Dockerfile.java.builder"
        else:
            raise ValueError(f"Unsupported language: {self.language}")

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        if oss_fuzz_project.project_metadata.language in [
            LanguageEnum.c,
            LanguageEnum.cpp,
        ]:
            return INSTRUMENTATION_DIR / "Dockerfile.c.runner"
        elif oss_fuzz_project.project_metadata.language == LanguageEnum.jvm:
            return INSTRUMENTATION_DIR / "Dockerfile.java.runner"
        else:
            raise ValueError(f"Unsupported language: {self.language}")
