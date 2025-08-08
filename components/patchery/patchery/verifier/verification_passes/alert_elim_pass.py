from .base_verification_pass import BaseVerificationPass
from ...data import JAZZER_CMD_INJECT_STR
from kumushi.data import Program, ProgramExitType


class AlertEliminationVerificationPass(BaseVerificationPass):
    FAIL_ON_EXCEPTION = True

    def __init__(self, *args, requires_executor=True, **kwargs):
        super().__init__(*args, requires_executor=requires_executor, **kwargs)

    def _verify(self):
        """
        Takes a ProgramInfo, which contains a target location and an alert type (like a sanitizer alert), and checks
        that after patching the self._program using triggering input no longer triggers the alert.

        :param patch:
        :param self._prog_info:
        :return:
        """
        reasoning = None
        passed = True
        for alerting_input in self._prog_info._crashing_inputs:
            exit_type, pov_report, stack_trace = self._prog_info.generates_alerts(alerting_input)
            if exit_type == ProgramExitType.TRIGGERED:
                self.crashing_function = stack_trace[0] if stack_trace else None
                if (
                    "AICC" in str(self._prog_info)
                    and self._prog_info.sanitizer_string is not None
                    and JAZZER_CMD_INJECT_STR not in self._prog_info.sanitizer_string
                ):
                    reasoning = f"Bug still triggered: {self._prog_info.sanitizer_string}"
                else:
                    # TODO: make a better reason in the general case
                    if pov_report:
                        reasoning = "Bug still triggered after patching \n" + str(pov_report)
                    else:
                        reasoning = "Bug still triggered after patching"
                passed = False
            elif exit_type == ProgramExitType.INTERNAL_ERROR:
                reasoning = "Internal error occurred during alert elimination check"
                passed = False
            elif exit_type == ProgramExitType.TIMEOUT:
                reasoning = "Timeout occurred during alert elimination check"
                passed = False

        return passed, reasoning
