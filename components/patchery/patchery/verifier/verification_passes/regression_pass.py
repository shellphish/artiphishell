import ast
import logging
import typing
from typing import Tuple

from kumushi.data import ProgramInput, ProgramInputType, ProgramExitType
from analysis_graph.models.crashes import BucketNode
from .base_verification_pass import BaseVerificationPass
from .fuzz_pass import INPUT_INFO

if typing.TYPE_CHECKING:
    from patchery.verifier import PatchVerifier

REASONING = """
## Patch Failed
The patch did not eliminate the crash for the following crashing inputs that are related to the original crash:

This was the patch that was applied:
### Patch 
```
%s
```
%s
"""
CRASH_INFO = """
The following stack trace was generated when we rerun all the crashing inputs that were related to the original crash:
### Stack Trace
```
%s
```

Note, that this crash is related to the original crash, but is not the same crash.

"""



_l = logging.getLogger(__name__)

class RegressionPass(BaseVerificationPass):
    def __init__(self, *args, verifier: "PatchVerifier" = None, **kwargs):
        self._verifier = verifier
        assert self._verifier is not None, "RegressionPass requires a verifier"
        super().__init__(*args, **kwargs)

    def locate_bucket(self) -> list[BucketNode]:
        report_key = self._prog_info.poi_report.crash_report_id
        buckets = BucketNode.nodes.all()
        found_buckets = []
        for bucket in buckets:
            pov_keys = [pov.key for pov in bucket.contain_povs.all()]
            if report_key in pov_keys:
                _l.info(f"Bucket {bucket.bucket_key} found")
                return [bucket]
        return found_buckets

    def _verify(self):
        """
        This pass checks if our patch mitigate all the relevant pov
        :return: Tuple of (passed: bool, reasoning: str)
        """
        passed = True  # Assume no regressions by default
        reasoning = "No regressions detected."  # Default reasoning
        bucket_key = self._prog_info.patch_request_metadata.bucket_id
        if bucket_key is None:
            _l.warning("No bucket key found in patch request metadata, cannot run regression pass.")
            return passed, reasoning
        buckets = BucketNode.nodes.filter(bucket_key=bucket_key).all()
        if not buckets:
            buckets = self.locate_bucket()
        if not buckets:
            return passed, reasoning
        all_crash_inputs = []
        for bucket in buckets:
            povs = bucket.contain_povs.all()
            for pov in povs:
                harness_inputs = pov.harness_inputs.all()
                if not harness_inputs:
                    continue
                for harness_input in harness_inputs:
                    if harness_input.crashing:
                        all_crash_inputs.append(ast.literal_eval(harness_input.content_escaped))
                        break

        _l.info(f"Found {len(all_crash_inputs)} crashing inputs in POV buckets")

        all_crash_info = ""
        # check the first 20 crahsing inputs and stop at the first crash found
        for crash_input in all_crash_inputs[:20]:
            crashes, crash_info, stack_trace = self.run_pov(crash_input)
            if crashes and self._crash_in_relevant_location(stack_trace):
                passed = False
                all_crash_info += crash_info
                break

        if passed:
            _l.info(f"No previous POV was found to crash after patching!")
        else:
            _l.info(f"Found crashing inputs in POV buckets that still crash after patching!")

        if self._verifier.regression_fuzzing_dir is not None and self._verifier.regression_fuzzing_dir.exists():
            _l.info("Running previously found crashing inputs from fuzzing...")
            for crash_input in list(self._verifier.regression_fuzzing_dir.iterdir())[:5]:
                crashes, crash_info, stack_trace = self.run_pov(crash_input)
                if crashes and self._crash_in_relevant_location(stack_trace):
                    passed = False
                    all_crash_info += crash_info
                    break

        if passed:
            _l.info("No regressions found in previously crashing inputs from fuzzing!")
        else:
            _l.info("Found previously crashing inputs from fuzzing that still crash after patching!")

        if not passed:
            reasoning = REASONING % (self._patch.diff, all_crash_info)
            return passed, reasoning

        return passed, reasoning

    def should_skip(self) -> Tuple[bool, str]:

        # if self._prog_info.language not in ["c", "C", "cpp", "c++"]:
        #     return True, "Regression verification pass is only applicable to C/C++ programs."

        if not self.smart_mode:
            return True, "Regression pass is only applicable to smart modes."
        return super().should_skip()

    def _crash_in_relevant_location(self, stack_trace: list[str]) -> bool:
        stack_trace_slice = stack_trace[:3]
        patched_functions = [f.function_name for f in  self._patch.patched_functions if f and f.function_name]
        # if any intersection exists between the patched functions and the stack trace, we consider it a relevant crash
        if any(func in stack_trace_slice for func in patched_functions):
            _l.info("Fuzzer discovered crash in a patched function: %s", stack_trace_slice)
            return True

        if stack_trace_slice and self._prog_info.crashing_function == stack_trace_slice[0]:
            _l.info("Fuzzer discovered crash in the original crashing function: %s", self._prog_info.crashing_function)
            return True

        return False

    def run_pov(self, pov_data: bytes) -> tuple[bool, str, list[str]]:

        input_obj = ProgramInput(pov_data, ProgramInputType.STDIN)
        exit_type, pov_report, stack_trace_funcs = self._prog_info.generates_alerts(input_obj)
        if exit_type == ProgramExitType.TRIGGERED:
            san_info = "unknown"
            if ("AICC" in str(self._prog_info)
                and self._prog_info.sanitizer_string is not None
            ):
                san_info = self._prog_info.sanitizer_string
            crash_info = f"Bug still triggered after patching with sanitizer: {san_info}\n"
            crash_info += f"\n {pov_report}"
            reasoning = CRASH_INFO % crash_info
            if input_obj.is_human_readable() and len(input_obj.data) < 5000:
                reasoning += INPUT_INFO % input_obj.data.decode('utf-8', errors='replace')

            crashes = True
        elif exit_type == ProgramExitType.INTERNAL_ERROR:
            reasoning = "Internal error occurred during alert elimination check"
            crashes = True
        elif exit_type == ProgramExitType.TIMEOUT:
            reasoning = "Timeout occurred during alert elimination check"
            crashes = True
        else:
            reasoning = "No crash occurred during alert elimination check"
            crashes = False

        return crashes, reasoning, stack_trace_funcs