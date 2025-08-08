import hashlib
import logging
import os
import shutil
import tempfile
import subprocess
import threading
import time
import typing
import uuid
from pathlib import Path
from typing import Optional

from shellphish_crs_utils.oss_fuzz.instrumentation.jazzer import JazzerInstrumentation

from kumushi.data import ProgramExitType
from .base_verification_pass import BaseVerificationPass
from kumushi.data.program_input import ProgramInput, ProgramInputType
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.aflpp import AFLPPInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.aijon import AIJONInstrumentation

if typing.TYPE_CHECKING:
    from patchery.verifier import PatchVerifier

AIJON_AVAILABLE = False
annotate_from_patch = None
from ...data import JAZZER_CMD_INJECT_STR

import litellm
litellm.set_verbose = False

_l = logging.getLogger(__name__)

REASONING = """
## Fuzzing Patch Failed
The patched program was fuzzed, but after a few seconds of fuzzing, it crashed.
This indicates that the patch introduced a bug or instability in the program.

This was the patch that was applied:
### Patch 
```
%s
```

The following stack trace was generated during the fuzzing process:
### Stack Trace
```
%s
```

Note, that this crash is related to the original crash, but is not the same crash.
"""

INPUT_INFO = """

### Input Information
The following input caused the crash which was found during fuzzing:
```
%s
```
"""

BINARY_LANGS = {"c", "cpp", "c++"}

FUZZING_LOCK = threading.Lock()

class FuzzVerificationPass(BaseVerificationPass):
    TIMEOUT = 60*15 # 15 minutes

    TOTAL_FUZZING_TIME = 60*5  # 5 minutes
    THREAD_FUZZING = False
    USE_AIJON = False
    SAVE_CRASHES = True
    def __init__(self, *args, verifier: "PatchVerifier" = None, **kwargs):
        self._verifier = verifier
        assert self._verifier is not None, "FuzzVerificationPass requires a verifier"
        super().__init__(*args, **kwargs)
        self.save_folder = f"/shared/patchery/{self._prog_info.poi_report.project_id}"

    def _prepare_seeds(self, make_dummy_input=False, save_loc: Path = None, zip_seeds=True) -> Path:
        # Create a seed corpus from crashing inputs
        os.makedirs(self.save_folder, exist_ok=True)
        corpus_dir = tempfile.mkdtemp(dir=self.save_folder)

        # Collect inputs and ensure we have at least 3
        inputs = []
        if hasattr(self._prog_info, "_crashing_inputs") and self._prog_info._crashing_inputs:
            inputs = self._prog_info._crashing_inputs

        # If we have fewer than 3 inputs, duplicate some to reach 3
        original_inputs = inputs.copy()
        while len(inputs) < 3 and original_inputs:
            inputs.append(original_inputs[0])

        if make_dummy_input:
            dummy_input = ProgramInput(b'fuzz', ProgramInputType.STDIN)
            inputs.append(dummy_input)

        # Save inputs to files and add to zip
        if zip_seeds:
            import zipfile
            corpus_zip = Path(corpus_dir) / f"{self._prog_info.poi_report.cp_harness_name}_seed_corpus.zip"
            save_loc = corpus_zip
            with zipfile.ZipFile(corpus_zip, 'w') as zipf:
                for i, input_data in enumerate(inputs):
                    input_path = Path(corpus_dir) / f"input_{i}"
                    try:
                        with open(input_path, 'wb') as f:
                            f.write(input_data.data)
                        zipf.write(input_path, arcname=f"input_{i}")
                    except Exception as e:
                        _l.error(f"Failed to process input {i}: {e}")
            _l.info(f"Created seed corpus at {corpus_zip} with {len(inputs)} inputs")
        elif save_loc and not zip_seeds:
            # copy the inputs to the save location
            for i, input_data in enumerate(inputs):
                input_path = Path(save_loc) / f"input_{i}"
                try:
                    with open(input_path, 'wb') as f:
                        f.write(input_data.data)
                except Exception as e:
                    _l.error(f"Failed to save input {i}: {e}")
            _l.info(f"Created seed corpus at {save_loc} with {len(inputs)} inputs")
        else:
            raise ValueError("Either zip_seeds must be True or save_loc must be provided.")

        return save_loc

    def _setup_fuzzer(self, timeout=TOTAL_FUZZING_TIME, use_aijon: bool = USE_AIJON, sync_inst_dir: Path = None) -> tuple[InstrumentedOssFuzzProject, Path, dict]:
        is_java = self._prog_info.language in {"java", "jvm"}
        is_binary = self._prog_info.language in BINARY_LANGS

        #
        # setup the environment for fuzzing
        #

        project_dir = Path(tempfile.TemporaryDirectory(dir=self.save_folder).name)
        inter_sync_dir = Path(tempfile.mkdtemp(dir=sync_inst_dir, suffix="inter_sync"))
        fuzz_envs = {
            'ARTIPHISHELL_DO_NOT_CREATE_INPUT': '1',
            'FORCED_CREATE_INITIAL_INPUT': '1',
            'FORCED_FUZZER_TIMEOUT': '4',
            'FORCED_DO_CMPLOG': '1',
            'FORCED_USE_CUSTOM_MUTATOR': '1',
            'FORCED_USE_AFLPP_DICT': '0',
            'FORCED_USE_CORPUSGUY_DICT': '0',
            "ARTIPHISHELL_AFL_TIMEOUT": str(timeout),
            'ARTIPHISHELL_INTER_HARNESS_SYNC_DIR': str(inter_sync_dir),
        }
        if is_java:
            # corpus dir needs to be manually created for Jazzer
            corp_save_loc = sync_inst_dir / "corpus"
            corp_save_loc.mkdir(parents=True, exist_ok=True)
            corpus_location = self._prepare_seeds(zip_seeds=False, save_loc=corp_save_loc)

            fuzz_envs['FUZZING_ENGINE'] = "libfuzzer"
            fuzz_envs['ARTIPHISHELL_JAZZER_BENIGN_SEEDS'] = str(corp_save_loc)
            fuzz_envs['ARTIPHISHELL_JAZZER_CRASHING_SEEDS'] = str(sync_inst_dir / "crashes")
            if use_aijon:
                raise ValueError("AIJON instrumentation is not supported for Java projects.")
        elif is_binary:
            corpus_location = self._prepare_seeds(zip_seeds=True)
            fuzz_envs['FUZZING_ENGINE'] = "shellphish_aflpp" if not use_aijon else "shellphish_aijon"
        else:
            raise ValueError("Unsupported language!")

        subprocess.run(
            f'rsync -a --delete --ignore-missing-args {self._prog_info.target_project.project_path} {project_dir}',
            shell=True)
        project_dir = project_dir / self._prog_info.target_project.project_path.name
        shutil.rmtree(project_dir / "artifacts", ignore_errors=True)
        subprocess.run(f"mkdir -p artifacts", shell=True, cwd=project_dir)

        # write the patch to a temporary file
        patch_dir = Path(tempfile.mkdtemp(dir=self.save_folder))
        with open(patch_dir / 'patch', 'w') as f:
            f.write(self._patch.diff)
        patch_path = patch_dir / 'patch'

        if use_aijon:
            if is_java:
                raise ValueError("AIJON instrumentation is not supported for Java projects.")

            _l.info("Using AIJON instrumentation for fuzzing")
            instrumentation = AIJONInstrumentation()
            patch_path = Path(
                annotate_from_patch(
                    patch_path, self._prog_info.source_root, self._prog_info.code._function_resolver,
                    language=self._prog_info.language
                )
            )
            patch_data = patch_path.read_text()
            if not patch_data:
                _l.warning("AIJON instrumentation was requested, but the patch is empty.")
                raise RuntimeError("Empty patch after AIJON annotation.")

            if "IJON" not in patch_data:
                _l.warning("AIJON instrumentation was requested, but the patch does not contain AIJON annotations.")
                raise RuntimeError("AIJON annotations not found in the patch after AIJON annotation.")
        elif is_binary:
            _l.info("Using AFL++ instrumentation for fuzzing")
            instrumentation = AFLPPInstrumentation()
        elif is_java:
            _l.info("Using Jazzer instrumentation for fuzzing")
            instrumentation = JazzerInstrumentation()

        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            oss_fuzz_project_path=project_dir,
            project_source=self._prog_info.target_project.project_source,
            project_id=self._prog_info.target_project.project_id,
            use_task_service=self._prog_info.target_project.use_task_service,
            augmented_metadata=self._prog_info.target_project.augmented_metadata
        )
        build_res = instr_project.build_target(patch_path=patch_path, sanitizer=self._prog_info.poi_report.sanitizer)
        if build_res.build_success and is_binary:
            # we copy over a zip in binary mode
            shutil.copy(corpus_location, project_dir / "artifacts" / 'out')

        seed_corpus_dir = project_dir / "artifacts" / 'out'
        return instr_project, seed_corpus_dir, fuzz_envs

    def _save_crash_dir(self, crash_dir: Path):
        if self._prog_info.bypassing_input_path is not None:
            self._prog_info.bypassing_input_path.mkdir(parents=True, exist_ok=True)
            # make a dirname based on time
            dir_name = str(int(time.time()))
            dir_path = self._prog_info.bypassing_input_path / dir_name
            dir_path.mkdir(parents=True, exist_ok=True)
            shutil.copytree(crash_dir, dir_path, dirs_exist_ok=True)
            _l.info("Saved crash inputs to %s", dir_path)

    def _fuzz_core(self, instance_name, sync_dir, timeout=TOTAL_FUZZING_TIME, use_aijon: bool = USE_AIJON, threaded=False) -> Optional[threading.Thread]:
        sync_inst_dir = sync_dir / instance_name
        fuzzer, seed_corpus_dir, fuzz_envs = self._setup_fuzzer(timeout=timeout, use_aijon=use_aijon, sync_inst_dir=sync_inst_dir)

        def _run_fuzzer():
            fuzzer.fuzz_harness(
                sanitizer=self._prog_info.poi_report.sanitizer,
                fuzzing_engine=self._prog_info.poi_report.fuzzer,
                harness=self._prog_info.poi_report.cp_harness_name,
                extra_env=fuzz_envs,
                instance_name=instance_name,
                sync_dir=str(sync_dir),
                timeout=timeout,
                use_tmp_shm=False,
            )
            if self.SAVE_CRASHES:
                # save all crashing inputs regardless of whether we found a valid crash or not
                crash_dir_path = sync_inst_dir / 'crashes'
                if crash_dir_path.exists() and crash_dir_path.is_dir():
                    self._save_crash_dir(crash_dir_path)
                else:
                    _l.error("Somehow the crash directory %s does not exist or is not a directory.", crash_dir_path)

        if threaded:
            thread = threading.Thread(target=_run_fuzzer, daemon=True)
            thread.start()
            time.sleep(2)
            if not thread.is_alive():
                raise RuntimeError("Fuzzer thread failed")
        else:
            thread = None
            _run_fuzzer()

        return thread

    def _wait_for_valid_crash(self, crash_dir_path, fuzzing_thread, timeout=TOTAL_FUZZING_TIME) -> tuple[Optional[Path], Optional[str]]:

        crash_found = False
        crash_file = None
        crash_info = None

        tested_crashes = set()
        crash_dir_path.mkdir(parents=True, exist_ok=True)
        start_time = time.time()
        _l.info("Waiting for valid crashes in %s", crash_dir_path)
        while time.time() - start_time < timeout:
            crash_inputs = list(crash_dir_path.iterdir())
            _l.info(f"Found {len(crash_inputs)} crash inputs in {crash_dir_path}")
            for crash_file in crash_inputs:
                if crash_file.suffix == '.txt':
                    continue

                if crash_file in tested_crashes:
                    continue

                tested_crashes.add(crash_file)
                if crash_file.is_file() and crash_file.stat().st_size > 0:
                    crashes, crash_info, stack_trace = self.run_pov(crash_file)
                    if crashes and stack_trace:
                        if self._crash_in_relevant_location(stack_trace):
                            _l.info(f"Found a crash input that reproduces the issue: {crash_file}")
                            crash_found = True
                            break

            if crash_found:
                break
            else:
                if fuzzing_thread is None or not fuzzing_thread.is_alive():
                    break
                time.sleep(5)

        _l.info("Finished waiting for valid crashes!")
        return (crash_file, crash_info) if crash_found else (None, None)


    def _fuzz_for_crashes(self, timeout=TOTAL_FUZZING_TIME):
        instance_name = f"patcher-fuzz-{str(uuid.uuid4())[:8]}"
        sync_dir = Path(tempfile.mkdtemp(dir=self.save_folder))
        # make sure that crashes directory exists
        crash_dir_path = sync_dir / instance_name / 'crashes'
        crash_dir_path.mkdir(parents=True, exist_ok=True)
        _l.info(f"Fuzzing crash dir path: %s", crash_dir_path)

        _l.info("Fuzzing patch %s with fuzzer %s for %d seconds", self._patch.diff, self._prog_info.poi_report.fuzzer, timeout)
        with FUZZING_LOCK:
            if self._verifier._patcher and not self._verifier._patcher.should_work:
                _l.warning("The patcher is shutting down all threads! Stopping fuzzing...")
                return False, "Patcher is shutting down"

            fuzz_failed = False
            use_aijon = self.USE_AIJON and AIJON_AVAILABLE
            if use_aijon:
                try:
                    fuzz_thread = self._fuzz_core(instance_name, sync_dir, timeout=timeout, use_aijon=True, threaded=self.THREAD_FUZZING)
                except Exception as e:
                    fuzz_failed = True
                    _l.critical(f"Failed to fuzz patch {instance_name}: {e} with AIJON instrumentation. Falling back to AFL++...")

            if not use_aijon or fuzz_failed:
                fuzz_thread = self._fuzz_core(instance_name, sync_dir, timeout=timeout, use_aijon=False, threaded=self.THREAD_FUZZING)

            _l.info("Waiting for a valid fuzzing crash...")
            valid_crash_path, crash_info = self._wait_for_valid_crash(crash_dir_path, fuzz_thread, timeout=(timeout if self.THREAD_FUZZING else 4))

        if self.SAVE_CRASHES:
            # save only the reproducing crash input to the regression dir
            if self._verifier.regression_fuzzing_dir and valid_crash_path is not None:
                with open(valid_crash_path, 'rb') as crash_file:
                    crash_data = crash_file.read()

                md5_hash = hashlib.md5(crash_data).hexdigest()
                new_crash_save = self._verifier.regression_fuzzing_dir / f"{md5_hash}"
                with open(new_crash_save, 'wb') as f:
                    f.write(crash_data)

        # congratz, no crashes found
        if valid_crash_path is None:
            if len(list(crash_dir_path.iterdir())) != 0:
                _l.warning("Unable to reproduce a crash with any fuzzer found crash. The patch may be unstable, but no valid crash inputs were found.")
                return True, "No valid crash inputs found (no reproduce)."

            return True, "No crashes found."
        else:
            _l.info("Found a crash input that reproduces the issue! The patch is bad!")
            return False, crash_info

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

    def run_pov(self, pov_file: Path) -> tuple[bool, str, list[str]]:
        with open(pov_file, 'rb') as pov_file:
            input_obj = ProgramInput(pov_file.read(), ProgramInputType.STDIN)

        exit_type, pov_report, stack_trace_funcs = self._prog_info.generates_alerts(input_obj)
        if exit_type == ProgramExitType.TRIGGERED:
            san_info = "unknown"
            if ("AICC" in str(self._prog_info)
                and self._prog_info.sanitizer_string is not None
                and JAZZER_CMD_INJECT_STR not in self._prog_info.sanitizer_string
            ):
                san_info = self._prog_info.sanitizer_string
            crash_info = f"Bug still triggered after patching with sanitizer: {san_info}\n"
            crash_info += f"\n {pov_report}"
            reasoning = REASONING % (self._patch.diff, crash_info)
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

    def _verify(self):
        no_crash, crash_info = self._fuzz_for_crashes()
        return no_crash, crash_info

    def should_skip(self):
        if not self._prog_info.crashing_function:
            _l.critical("No crashing function set in program info, cannot run fuzz verification pass.")
            return True, "No crashing function set in program info."

        if not self.smart_mode:
            return True, "Fuzz verification pass is only applicable to smart modes."

        return super().should_skip()