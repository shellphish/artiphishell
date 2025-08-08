import os
from pathlib import Path
import shutil

from shellphish_crs_utils import C_INSTRUMENTATION_DIR, LIBS_DIR
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

INSTRUMENTATION_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__))))

@supported_instrumentation
class AFLPPInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "shellphish_aflpp"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        shutil.copy(str(C_INSTRUMENTATION_DIR / "anti-wrap-ld.sh"), str(INSTRUMENTATION_DIR))
        shutil.copy(str(C_INSTRUMENTATION_DIR / "generic_harness.c"), str(INSTRUMENTATION_DIR))
        shutil.copy(shutil.which("yq"), str(INSTRUMENTATION_DIR))

        # Nautilus
        src_path = LIBS_DIR / "nautilus"
        dst_path = INSTRUMENTATION_DIR / "nautilus"
        shutil.copytree(str(src_path), str(dst_path), dirs_exist_ok=True)
        st = os.stat(str(src_path))
        os.chown(str(dst_path), st.st_uid, st.st_gid)
        shutil.rmtree(str(dst_path / "target"), ignore_errors=True) # clear build dir of cached obj files w/ wrong libc version

        return INSTRUMENTATION_DIR

    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.prebuild"

    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.builder"

    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return INSTRUMENTATION_DIR / "Dockerfile.runner"
