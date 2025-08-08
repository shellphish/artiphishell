import os
from pathlib import Path
from shellphish_crs_utils.oss_fuzz.instrumentation import Instrumentation, supported_instrumentation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

EMPTY_DIR = '/tmp/shellphish-instrumentation-empty-dir'
os.makedirs(EMPTY_DIR, exist_ok=True)

@supported_instrumentation
class BuiltinLibfuzzerInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "libfuzzer"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return Path(EMPTY_DIR)

@supported_instrumentation
class BuiltinAFLInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "afl"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return Path(EMPTY_DIR)

@supported_instrumentation
class BuiltinHonggfuzzInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "honggfuzz"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return Path(EMPTY_DIR)

@supported_instrumentation
class BuiltinCentipedeInstrumentation(Instrumentation):
    def get_tool_name(self) -> str:
        return "centipede"

    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return Path(EMPTY_DIR)
