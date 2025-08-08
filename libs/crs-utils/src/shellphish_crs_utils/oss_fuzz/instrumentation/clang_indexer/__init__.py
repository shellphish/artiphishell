import os
from pathlib import Path
import shutil
from typing import Optional
from shellphish_crs_utils import C_INSTRUMENTATION_DIR, LIBS_DIR
from shellphish_crs_utils.oss_fuzz.instrumentation import (
    Instrumentation,
    supported_instrumentation,
)
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))


@supported_instrumentation
class ClangIndexerInstrumentation(Instrumentation):
    def get_tool_name(self, use_alias=True) -> str:
        return "clang_indexer"

    def _internal_tool_replacement_alias(self) -> Optional[str]:
        return 'libfuzzer'

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        shutil.copy(
            str(LIBS_DIR / "crs-utils" / "src" / "shellphish_crs_utils" / "oss_fuzz" / "target_info.py"),
            str(INSTRUMENTATION_DIR / "clang-indexer" / "src" / "clang_indexer" / "target_info.py")
        )
        return INSTRUMENTATION_DIR

    def get_prebuild_dockerfile(self, oss_fuzz_project):
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.builder"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None
