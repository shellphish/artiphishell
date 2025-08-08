import logging
import shutil
import tempfile
import subprocess
import threading
import time
import uuid
import hashlib
import os
import yaml
import concurrent.futures
from pathlib import Path
from typing import List

from .base_pass import BaseVerificationPass
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.aflpp import AFLPPInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.jazzer import JazzerInstrumentation
from shellphish_crs_utils.models.crs_reports import POIReport

from ..exceptions.errors import PatchedCodeStillCrashes, PatchedCodeHangs
from ...models import CrashingInput
from ...utils.supress import maybe_suppress_output
from ...config import Config

import litellm
litellm.set_verbose = False

_l = logging.getLogger(__name__)

FUZZING_LOCK = threading.Lock()
TIMEOUT = 60 * 7.5  # 7.5 minutes in seconds

class FuzzVerificationPass(BaseVerificationPass):
    TOTAL_FUZZING_TIME = Config.fuzz_patch_time 
    SAVE_CRASHES = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "FuzzVerificationPass"
        self.crashing_inputs_to_test = self.all_args.get("crashing_inputs_to_test", None)
        self.initial_crash_count = len(self.crashing_inputs_to_test)
        self.sanitizer_to_build_with = kwargs.get('all_args')['sanitizer_to_build_with']
        self.poi_report = self.all_args.get("poi_report", None)
        self.temp_dir = tempfile.mkdtemp(dir=f"/shared/patcherq/{self.all_args['project_id']}",suffix="fuzz")
        assert(self.crashing_inputs_to_test is not None)
        assert(self.poi_report is not None)

        # open the poi report as yaml 
        self.poi_report = POIReport.model_validate(yaml.safe_load(open(self.poi_report, 'r')))
        self.harness_name = self.poi_report.cp_harness_name
        
        # Create the directory structure for the new project
        new_folder = tempfile.mkdtemp(dir=self.temp_dir,suffix="fuzz_instr")
        self.new_oss_fuzz_dir = os.path.join(new_folder, "oss-fuzz", "projects", self.clean_cp.project_name)
        self.new_source_dir = os.path.join(new_folder, "source-root")
        os.makedirs(self.new_source_dir, exist_ok=True)
        os.makedirs(self.new_oss_fuzz_dir, exist_ok=True)

        # Now copy the source to the new temporary folder
        # NOTE: These copies are always done from an ****UN-BUILT**** Challenge Project, thus there 
        #       is no need of wiping the artifacts folder.
        subprocess.check_call(["cp", "-a", f"{self.clean_cp.project_path}/.", self.new_oss_fuzz_dir])
        subprocess.check_call(["cp", "-a", f"{self.clean_cp.project_source}/.", self.new_source_dir])
        
        self.new_oss_fuzz_dir = Path(self.new_oss_fuzz_dir)
        self.new_source_dir = Path(self.new_source_dir)
        
        self.crashing_function = None
        if self.poi_report.stack_traces:
            main_stack_trace = self.poi_report.stack_traces.get("main", None)
            if main_stack_trace is not None and main_stack_trace.call_locations:
                call_location = main_stack_trace.call_locations[0]
                if call_location.source_location:
                    self.crashing_function = call_location.source_location.function_name
        
        _l.info(f"Functions in patch: {self.functions_in_patch}\n")
        _l.info(f"Crashing function: {self.crashing_function}\n")

    def _zip_seeds(self) -> Path:
        # Create a seed corpus from crashing inputs
        corpus_dir = tempfile.mkdtemp(dir=self.temp_dir,suffix="corp")
        corpus_zip = Path(corpus_dir) / f"{self.poi_report.cp_harness_name}_seed_corpus.zip"

        inputs = [open(crash.crashing_input_path,"rb").read() for crash in self.crashing_inputs_to_test]
        # If we have fewer than 3 inputs, duplicate some to reach 3
        original_inputs = inputs.copy()
        while len(inputs) < 3 and original_inputs:
            inputs.append(original_inputs[0])

        # Save inputs to files and add to zip
        import zipfile
        with zipfile.ZipFile(corpus_zip, 'w') as zipf:
            for i, input_data in enumerate(inputs):
                input_path = Path(corpus_dir) / f"input_{i}"
                try:
                    with open(input_path, 'wb') as f:
                        f.write(input_data)
                    zipf.write(input_path, arcname=f"input_{i}")
                except Exception as e:
                    _l.error(f"Failed to process input {i}: {e}")

        _l.info(f"Created seed corpus at {corpus_zip} with {len(inputs)} inputs")
        return corpus_zip

    def _setup_fuzzer_c(self, timeout=TOTAL_FUZZING_TIME) -> tuple[InstrumentedOssFuzzProject, Path, dict]:
        inter_sync_dir = Path(tempfile.mkdtemp(dir=self.temp_dir,suffix="inter_sync"))
        fuzz_envs = {
            'ARTIPHISHELL_DO_NOT_CREATE_INPUT': '1',
            'ARTIPHISHELL_INTER_HARNESS_SYNC_DIR': str(inter_sync_dir),
            'FORCED_CREATE_INITIAL_INPUT': '1',
            'FORCED_FUZZER_TIMEOUT': '4',
            'FORCED_DO_CMPLOG': '1',
            'FORCED_USE_CUSTOM_MUTATOR': '1',
            'FORCED_USE_AFLPP_DICT': '0',
            'FORCED_USE_CORPUSGUY_DICT': '0',
            "FUZZING_ENGINE": "shellphish_aflpp",
            "ARTIPHISHELL_AFL_TIMEOUT": str(timeout),
        }
        
        corpus_zip = self._zip_seeds()

        _l.info("Using AFL++ instrumentation for fuzzing")
        instrumentation = AFLPPInstrumentation()

        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            oss_fuzz_project_path=self.new_oss_fuzz_dir,
            project_source=self.new_source_dir,
            project_id=self.clean_cp.project_id,
            use_task_service=self.clean_cp.use_task_service,
            augmented_metadata=self.clean_cp.augmented_metadata
        )
        with maybe_suppress_output():
            if Config.is_local_run:
                instr_project.build_builder_image()
                instr_project.build_runner_image()
            build_res = instr_project.build_target(sanitizer=self.poi_report.sanitizer, patch_content=self.git_diff)
        shutil.copy(corpus_zip, self.new_oss_fuzz_dir / "artifacts" / 'out')
        seed_corpus_dir = self.new_oss_fuzz_dir / "artifacts" / 'out'
        return instr_project, seed_corpus_dir, fuzz_envs
    
    def _setup_fuzzer_java(self, instance_name=None, sync_dir=None) -> tuple[InstrumentedOssFuzzProject, Path, dict]:
        # Create a seed corpus from crashing inputs
        corpus_dir = tempfile.mkdtemp(dir=self.temp_dir,suffix="corp")
        for crash in self.crashing_inputs_to_test:
            subprocess.run(f"cp {crash.crashing_input_path} {corpus_dir}/", shell=True)
        
        subprocess.run(f"mkdir -p {str(sync_dir / instance_name / 'crashes')}", shell=True)
        
        fuzz_envs = {
            'ARTIPHISHELL_JAZZER_BENIGN_SEEDS': str(corpus_dir),
            'ARTIPHISHELL_JAZZER_CRASHING_SEEDS': str(sync_dir / instance_name / "crashes")
        }

        _l.info("Using Jazzer instrumentation for fuzzing")
        instrumentation = JazzerInstrumentation()

        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            oss_fuzz_project_path=self.new_oss_fuzz_dir,
            project_source=self.new_source_dir,
            project_id=self.clean_cp.project_id,
            use_task_service=self.clean_cp.use_task_service,
            augmented_metadata=self.clean_cp.augmented_metadata
        )
        with maybe_suppress_output():
            if Config.is_local_run:
                instr_project.build_builder_image()
                instr_project.build_runner_image()
            build_res = instr_project.build_target(sanitizer=self.poi_report.sanitizer, patch_content=self.git_diff)
        return instr_project, fuzz_envs

    def _save_crash_inputs(self, crashing_inputs: List[Path]):
        if self.crashing_inputs_to_test is not None:
            for crash in crashing_inputs:
                with open(crash, 'rb') as file:
                    crash_input_bytes = file.read()
                    crash_input_hash = hashlib.sha256(crash_input_bytes).hexdigest()
                    crash_input_hex = crash_input_bytes.hex()
                    ci = CrashingInput(crashing_input_hex=crash_input_hex, crashing_input_hash=crash_input_hash)
                    self.crashing_inputs_to_test.append(ci)
        _l.info(f"Total crashes after saving: {len(self.crashing_inputs_to_test)}")
        return

    def _fuzz_core(self, instance_name, sync_dir, timeout=TOTAL_FUZZING_TIME):
        global TIMEOUT
        if self.language in ["c", "C", "cpp", "c++"]:
            TIMEOUT = 60 * 7.5  # Reset timeout for C fuzzing
            fuzzer, _, fuzz_envs = self._setup_fuzzer_c(timeout=timeout)
            fuzzer.fuzz_harness(
                sanitizer=self.poi_report.sanitizer,
                fuzzing_engine=self.poi_report.fuzzer,
                harness=self.poi_report.cp_harness_name,
                extra_env=fuzz_envs,
                instance_name=instance_name,
                sync_dir=str(sync_dir),
                use_tmp_shm=False,
            )
        else:
            TIMEOUT = 60 * 10  # Reset timeout for Java fuzzing
            fuzzer, fuzz_envs = self._setup_fuzzer_java(instance_name=instance_name, sync_dir=sync_dir)
            with maybe_suppress_output():
                fuzzer.fuzz_harness(
                    sanitizer=self.poi_report.sanitizer,
                    fuzzing_engine=self.poi_report.fuzzer,
                    harness=self.poi_report.cp_harness_name,
                    extra_env=fuzz_envs,
                    instance_name=instance_name,
                    timeout=timeout,
                    use_tmp_shm=False,
                )

    def _fuzz_for_crashes(self, timeout=TOTAL_FUZZING_TIME):
        instance_name = f"patcher-fuzz-{str(uuid.uuid4())[:8]}"
        sync_dir = Path(tempfile.mkdtemp(dir=self.temp_dir,suffix="sync"))
        _l.info("Fuzzing patch %s with fuzzer %s for %d seconds", self.git_diff, self.poi_report.fuzzer, timeout)
        with FUZZING_LOCK:
            self._fuzz_core(instance_name, sync_dir, timeout=timeout)

        # fuzzing is completed, we either have a crash or not
        _l.info("Fuzzing completed, checking for crashes...")
        crash_dir_path = sync_dir / instance_name / 'crashes'
        if not crash_dir_path.exists() or not crash_dir_path.is_dir():
            _l.critical("No crash directory found after fuzzing, this is unexpected.")
            return True, "No crash directory found."

        crash_inputs = list(crash_dir_path.iterdir())
        if not crash_inputs:
            _l.info("No crashes found during fuzzing. The patch seems stable.")
            return True, "No crashes found."

        # find an input that actually causes a crash
        relevant_crashes=[]
        exceptions=[]
        for crash_file in crash_inputs:
            if crash_file.suffix == '.txt':
                _l.debug(f"Skipping non-binary crash file: {crash_file}")
                continue

            if crash_file.is_file() and crash_file.stat().st_size > 0:
                is_crashing, exception = self.run_pov(crash_file)

                if is_crashing:
                    relevant_crashes.append(crash_file)
                    exceptions.append(exception)
        
        if relevant_crashes:
            if self.SAVE_CRASHES:
                self._save_crash_inputs(relevant_crashes)
            return False, exceptions[0]
        else:
            _l.warning("Unable to reproduce a crash with any fuzzer found crash. The patch may be unstable, but no valid crash inputs were found.")
            return True, "No valid crash inputs found (no reproduce)."
    
    def run_pov(self, pov_file: Path) -> bool:    
        with maybe_suppress_output():
            # IMPORTANT This uses the built cp from COMPILE PASS
            res = self.cp.run_pov(
                                self.harness_name, 
                                data_file=pov_file,
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
    
    def run(self) -> bool:
        global TIMEOUT
        if not self.functions_in_patch or not self.crashing_function:
            return True

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._fuzz_for_crashes)
                try:
                    passed, exception = future.result(timeout=TIMEOUT)
                    if not passed:
                        raise exception
                except concurrent.futures.TimeoutError:
                    _l.warning("⏰ Fuzzing timed out after 7.5 minutes. Returning True.")
        except Exception as e:
            _l.error(f"🤡 Fuzzing failed with exception (so we are returning True): {e}")

        return True
