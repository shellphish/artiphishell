import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional
from shellphish_crs_utils import ARTIPHISHELL_DIR, LIBS_DIR, C_INSTRUMENTATION_DIR, BLOBS_DIR
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from subprocess import check_call

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))

@supported_instrumentation
class CoverageFastInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "coverage_fast"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        shutil.copy(str(C_INSTRUMENTATION_DIR / "anti-wrap-ld.sh"), str(INSTRUMENTATION_DIR))
        # replaced the COPY with WGET inside the Dockerfile
        # shutil.copy(str(BLOBS_DIR / "pin.tar.gz"), str(INSTRUMENTATION_DIR))
        
        return INSTRUMENTATION_DIR

    def _internal_tool_replacement_alias(self) -> Optional[str]:
        # This is gonna use compile_libfuzzer script for the
        # default compilation.
        return "libfuzzer"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        image_name_suffix = {
            LanguageEnum.c: "c",
            LanguageEnum.cpp: "c",
            LanguageEnum.jvm: "jvm"
        }[oss_fuzz_project.project_metadata.language]
        return INSTRUMENTATION_DIR / f"Dockerfile.builder.{image_name_suffix}"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        image_name_suffix = {
            LanguageEnum.c: "c",
            LanguageEnum.cpp: "c",
            LanguageEnum.jvm: "jvm"
        }[oss_fuzz_project.project_metadata.language]

        return INSTRUMENTATION_DIR / f"Dockerfile.runner.{image_name_suffix}"
    
    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:        
        return INSTRUMENTATION_DIR / f"Dockerfile.prebuild"

    def post_build(self, oss_fuzz_project: OSSFuzzProject) -> None:
        oss_fuzz_project_artifacts_out = oss_fuzz_project.artifacts_dir_out

        if oss_fuzz_project.project_metadata.language == LanguageEnum.jvm:
            subprocess.check_call([
                str(INSTRUMENTATION_DIR / "post-build-java.sh"),
            ],
            env = {
                'OUT': str(oss_fuzz_project_artifacts_out),
                'ARTIPHISHELL_DIR': str(ARTIPHISHELL_DIR),
                'INSTRUMENTATION_DIR': str(INSTRUMENTATION_DIR),
                'BUILT_PROJECT_PATH': str(oss_fuzz_project.project_path),
                # make sure it uses the same python interpreter we're currently running inside
                'PYTHON_INTERPRETER': sys.executable,
                **os.environ
            })

        pass
