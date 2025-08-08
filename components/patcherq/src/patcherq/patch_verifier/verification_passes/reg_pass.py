import logging
import yaml
import tempfile
from pathlib import Path

from shellphish_crs_utils.models.crs_reports import POIReport

from ...helper import Helper
from ...models import CrashingInput
from .base_pass import BaseVerificationPass
from ..exceptions.errors import PatchedCodeStillCrashes, PatchedCodeHangs

from ...utils.supress import maybe_suppress_output

_l = logging.getLogger(__name__)

class RegressionVerificationPass(BaseVerificationPass):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "RegressionPass"
        self.bucket_id = kwargs.get('all_args')['bucket_id']
        self.sanitizer_to_build_with = kwargs.get('all_args')['sanitizer_to_build_with']

        # open the poi report as yaml to get the harness name
        self.poi_report = self.all_args.get("poi_report", None)
        assert(self.poi_report is not None)
        self.poi_report = POIReport.model_validate(yaml.safe_load(open(self.poi_report, 'r')))
        self.harness_name = self.poi_report.cp_harness_name

        self.crashing_function = None
        if self.poi_report.stack_traces:
            main_stack_trace = self.poi_report.stack_traces.get("main", None)
            if main_stack_trace is not None and main_stack_trace.call_locations:
                call_location = main_stack_trace.call_locations[0]
                if call_location.source_location:
                    self.crashing_function = call_location.source_location.function_name
        
        _l.info(f"Functions in patch: {self.functions_in_patch}\n")
        _l.info(f"Crashing function: {self.crashing_function}\n")
    
    def _get_crashing_inputs(self):
        crashing_inputs = []
        crashing_input_nodes = Helper.get_crashing_inputs_from_bucket(self.bucket_id, 20)
        for crashing_input_node in crashing_input_nodes:
            ci = CrashingInput(
                crashing_input_hex=crashing_input_node[0].content_hex, 
                crashing_input_hash=crashing_input_node[0].content_hash
            )
            crashing_inputs.append(ci)
        return crashing_inputs

    def _crash_in_relevant_location(self, pov) -> bool:
        # If crash is not relevant dont care
        stack_trace_functions = []
        if pov is not None:
            if pov.crash_report is not None and pov.crash_report.stack_traces:
                main_stack_trace = pov.crash_report.stack_traces.get("main", None)
                if main_stack_trace is not None and main_stack_trace.call_locations:
                    for call_location in main_stack_trace.call_locations:
                        if call_location.source_location and call_location.source_location.function_name:
                            stack_trace_functions.append(call_location.source_location.function_name)
                        else:
                            stack_trace_functions.append("")

        stack_trace_slice = stack_trace_functions[:3]
        
        _l.info(f"Stack trace functions: {stack_trace_functions}\n")
        
        # if any intersection exists between the patched functions and the stack trace, we consider it a relevant crash
        if any(func in stack_trace_slice for func in self.functions_in_patch):
            _l.info("Fuzzer discovered crash in a patched function")
            return True
        
        if stack_trace_slice and self.crashing_function == stack_trace_slice[0]:
            _l.info("Fuzzer discovered crash in the original crashing function")
            return True

        return False

    def run_pov(self, crashing_input: CrashingInput):    
        with maybe_suppress_output():
            # IMPORTANT This uses the built cp from COMPILE PASS
            res = self.cp.run_pov(
                                    self.harness_name, 
                                    data_file=crashing_input.crashing_input_path,
                                    sanitizer=self.sanitizer_to_build_with,
                                    fuzzing_engine="libfuzzer",
                                    timeout=60*5
                                )
        stdout = res.stdout
        stderr = res.stderr

        _l.info(f'res.run_exit_code = {res.run_exit_code}')

        # If this happens, something is REALLY BAD
        assert res.run_exit_code != None
        
        if res.run_exit_code == 124:
            _l.info(f'Logs:\nSTDOUT:{str(stdout)}\nSTDERR:{str(stderr)}\n')
            # This is a TIMEOUT issue, the patch probably caused the program to hang now...
            with tempfile.NamedTemporaryFile(delete=False) as stderr_log:
                stderr_log.write(b'\n===EXECUTION STDERR START===\n')
                stderr_log.write(stderr)
                stderr_log.write(b'===EXECUTION STDERR END===\n')
                stderr_log.write(b'\n===EXECUTION STDOUT START===\n')
                stderr_log.write(stdout)
                stderr_log.write(b'===EXECUTION STDOUT END===\n')
            return True, PatchedCodeHangs(stderr_log.name, new_hang=True)

        if not self._crash_in_relevant_location(res.pov):
            return False, None

        if res.pov.crash_report or res.run_exit_code != 0:
            _l.info(f'Logs:\nSTDOUT:{str(stdout)}\nSTDERR:{str(stderr)}\n')
            if res.pov.crash_report:
                _l.info(f"  [DEBUG] The target crashed and we have a crash report | exit_code: {res.run_exit_code}")
                return True, PatchedCodeStillCrashes(str(res.pov.crash_report), new_crash=True)
            else:
                _l.info(f"  [DEBUG] The target crashed but we do not have a crash report | exit_code: {res.run_exit_code}")
                return True, PatchedCodeStillCrashes(f"Exit code: {res.run_exit_code}. No crash report available.", new_crash=True)
        else:
            assert(res.run_exit_code == 0), f"Unexpected exit code: {res.run_exit_code}. Expected 0."
            return True, None

    def run(self):
        """
        Run the regression verification pass.
        """
        try:
            crashing_inputs = self._get_crashing_inputs()
            _l.info(f"Found {len(crashing_inputs)} crashing inputs in bucket {self.bucket_id}.")
            _l.info(f"{crashing_inputs}")
            for crashing_input in crashing_inputs:
                # Run POV
                crashed, exception = self.run_pov(crashing_input)
                _l.info(f"Running POV = {crashed}, exception = {exception}")
                if crashed:
                    raise exception
        except Exception as e:
            _l.error(f"🤡 An error occurred during the regression verification pass: {e}")
        return True
            