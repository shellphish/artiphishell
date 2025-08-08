

import yaml
import os
import tempfile 
import logging

from agentlib import LLMFunction
from pathlib import Path

from ..exceptions.errors import PatchedCodeStillCrashes, PatchedCodeHangs
from .base_pass import BaseVerificationPass
from patcherq.config import Config, PatcherqMode
from ...utils.supress import maybe_suppress_output

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CrashVerificationPass(BaseVerificationPass):
    '''
    This pass is responsible for verifying that the patched code does not crash 
    when given the crashing input.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "CrashVerificationPass"
        self.crashing_input_path = self.all_args.get("crashing_input_path", None)
        self.sanitizer_to_build_with = kwargs.get('all_args')['sanitizer_to_build_with']
        self.poi_report = self.all_args.get("poi_report", None)
        self.functions_by_file_index = self.all_args.get("functions_by_file_index", None)
        assert(self.crashing_input_path is not None)
        assert(self.poi_report is not None)

        # open the poi report as yaml 
        with open(self.poi_report, "r") as f:
            self.poi_report = yaml.load(f, Loader=yaml.FullLoader)
        self.harness_name = self.poi_report["cp_harness_name"]

    def summarize_raw_crash_msg(self, text: str) -> str:
        summarizer_prompt = '''
        You are a professional security engineer and an incident response analyst.
        Given a raw message of a crash-report for a program, your task is to summarize the crash message into a single paragraph.
        You must keep only the file name and the reason of the crash.
        The raw crash message is {{ info.crash_message }}
        '''
        summarize_llm = LLMFunction.create(
            summarizer_prompt,
            model='gpt-4.1-mini', # TODO: Change the model to 'gpt-4o-mini' when it is available
            use_loggers=True,
            temperature=0.0
        )
        summarize_crash_report = summarize_llm(
            info = dict(
                crash_message = text,
                output_format = "Just output the summary of the crash message"
            )
        )
        return summarize_crash_report

    def run(self):
        crashing_inputs_to_test = self.all_args.get("crashing_inputs_to_test", None)
        assert crashing_inputs_to_test is not None, "crashing_inputs_to_test is None"

        patch_pass_this_number_of_crashing_input = 0
        logger.info(f"Testing {len(crashing_inputs_to_test)} crashing inputs")
        
        for crashing_input_id, crashing_input in enumerate(crashing_inputs_to_test):
            logger.info(f" 💣->💥❔ Testing crashing input {crashing_input.crashing_input_path} [{crashing_input_id+1}/{len(crashing_inputs_to_test)}]")
            with maybe_suppress_output():
              res = self.cp.run_pov(
                                  self.harness_name, 
                                  data_file=crashing_input.crashing_input_path,
                                  sanitizer=self.sanitizer_to_build_with,
                                  fuzzing_engine="libfuzzer",
                                  timeout=60*5
                                  )
            
            stdout = res.stdout
            stderr = res.stderr

            logger.info(f'res.run_exit_code = {res.run_exit_code}')

            # If this happens, something is REALLY BAD
            assert res.run_exit_code != None
            
            if res.run_exit_code == 124:
                logger.info(f'Logs:\nSTDOUT:{str(stdout)}\nSTDERR:{str(stderr)}\n')
                # This is a TIMEOUT issue, the patch probably caused the program to hang now...
                with tempfile.NamedTemporaryFile(delete=False) as stderr_log:
                    stderr_log.write(b'\n===EXECUTION STDERR START===\n')
                    stderr_log.write(stderr)
                    stderr_log.write(b'===EXECUTION STDERR END===\n')
                    stderr_log.write(b'\n===EXECUTION STDOUT START===\n')
                    stderr_log.write(stdout)
                    stderr_log.write(b'===EXECUTION STDOUT END===\n')
                raise PatchedCodeHangs(stderr_log.name, num_passed=patch_pass_this_number_of_crashing_input)
            elif res.pov.crash_report or res.run_exit_code != 0:
                logger.info(f'Logs:\nSTDOUT:{str(stdout)}\nSTDERR:{str(stderr)}\n')
                if res.pov.crash_report:
                    logger.info(f"  [DEBUG] The target crashed and we have a crash report {str(res.pov.crash_report)} | exit_code: {res.run_exit_code}")
                    raise PatchedCodeStillCrashes(str(res.pov.crash_report))
                else:
                    logger.info(f"  [DEBUG] The target crashed but we do not have a crash report | exit_code: {res.run_exit_code}")
                    raise PatchedCodeStillCrashes(f"Exit code: {res.run_exit_code}. No crash report available.", num_passed=patch_pass_this_number_of_crashing_input)
            else:
                assert(res.run_exit_code == 0), f"Unexpected exit code: {res.run_exit_code}. Expected 0."
                patch_pass_this_number_of_crashing_input += 1
        
        # We return True ONLY if all the crashing inputs passed the test
        return True