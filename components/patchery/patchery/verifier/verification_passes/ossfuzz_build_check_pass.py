import logging
from typing import Tuple

from kumushi.aixcc import AICCProgram
from .base_verification_pass import BaseVerificationPass

_l = logging.getLogger(__name__)

class OssFuzzBuildCheckPass(BaseVerificationPass):
    def _verify(self):
        # WARNING! THIS CODE MUST BE RUN AFTER A SUCCESSFUL COMPILE PASS!
        if not isinstance(self._prog_info, AICCProgram):
            raise TypeError("OssFuzzBuildCheckPass requires an AICCProgram instance")

        if not self._prog_info.build_checker_works:
            return True, "Build checker is not available, skipping OSS Fuzz build check"

        build_check_res = self._prog_info.target_project.run_ossfuzz_build_check(
            sanitizer=self._prog_info.sanitizer_string
        )
        if build_check_res.all_passed:
            if build_check_res.internal_error:
                _l.warning("Internal error occurred during OSS Fuzz build check, but all other checks passed.")
            return True, "OSS Fuzz build check passed"
        else:
            return False, "OSS Fuzz build_check failed. You patched or broke the fuzz harness!"

    def should_skip(self) -> Tuple[bool, str]:
        if not self.smart_mode:
            return True, "Skipping OSS Fuzz build check in non-smart mode"

        if not self._prog_info.build_checker_works:
            return True, "Build checker is not available, skipping OSS Fuzz build check"

        return super().should_skip()