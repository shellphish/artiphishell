from .base_verification_pass import BaseVerificationPass
from ...data import ProgramExitType
import os


class FunctionalityVerificationPass(BaseVerificationPass):
    def __init__(self, *args, requires_executor=True, **kwargs):
        super().__init__(*args, requires_executor=requires_executor, **kwargs)

    def _verify(self):
        # OSS Fuzz target does not implement run_tests
        exit_type = self._prog_info.executor.check_functionality()
        reasoning = None
        passed = True
        if exit_type == ProgramExitType.TRIGGERED:
            # TODO: make a better reason and resuse the old alert
            reasoning = "Functionality check failed after patching"
            passed = False
        elif exit_type == ProgramExitType.INTERNAL_ERROR:
            reasoning = "Internal error occurred during functionality check"
            passed = False

        return passed, reasoning
