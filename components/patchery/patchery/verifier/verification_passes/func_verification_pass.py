import logging
import yaml
from typing import Tuple

from kumushi.aixcc import AICCProgram
from .base_verification_pass import BaseVerificationPass
from shellphish_crs_utils.models.testguy import TestGuyMetaData

from kumushi.data import ProgramExitType

_l = logging.getLogger(__name__)

class FunctionalityVerificationPass(BaseVerificationPass):
    def __init__(self, *args, requires_executor=True, **kwargs):
        super().__init__(*args, requires_executor=requires_executor, **kwargs)

    def _verify(self):
        # OSS Fuzz target does not implement run_tests
        exit_type, fail_reason = self._prog_info.check_functionality(patch=self._patch)
        if exit_type == ProgramExitType.TEST_FAILED:
            ctx_lines = 20
            reasoning = f"Functionality tests failed after patching."
            if fail_reason:
                reasoning += f" Here are the last {ctx_lines} lines:\n...\n"
                fail_lines = fail_reason.splitlines()[-ctx_lines:]
                reasoning += "\n".join(fail_lines)
            passed = False
        elif exit_type == ProgramExitType.INTERNAL_ERROR:
            reasoning = "Internal error occurred during functionality check"
            passed = True
        else:
            reasoning = "Functionality check passed"
            passed = True

        return passed, reasoning
