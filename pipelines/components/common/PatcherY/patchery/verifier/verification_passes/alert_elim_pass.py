from .base_verification_pass import BaseVerificationPass
from ...data import ProgramExitType, JAZZER_CMD_INJECT_STR
from ...data.aicc import AICCProgramInfo


class AlertEliminationVerificationPass(BaseVerificationPass):
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
        for alerting_input in self._prog_info.alerting_inputs:
            exit_type = self._prog_info.executor.generates_alerts(alerting_input)
            if exit_type == ProgramExitType.TRIGGERED:
                if (
                    isinstance(self._prog_info, AICCProgramInfo)
                    and self._prog_info.sanitizer_string is not None
                    and JAZZER_CMD_INJECT_STR not in self._prog_info.sanitizer_string
                ):
                    reasoning = f"Bug still triggering: {self._prog_info.sanitizer_string}"
                else:
                    # TODO: make a better reason in the general case
                    reasoning = "Bug still triggered after patching"
                passed = False
            elif exit_type == ProgramExitType.INTERNAL_ERROR:
                reasoning = "Internal error occurred during alert elimination check"
                passed = False

        return passed, reasoning
