import logging
import os
import random
import shutil
import string
from pathlib import Path
from subprocess import run
from tempfile import NamedTemporaryFile

import yaml
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from QuickSeed.utils import run_crash_input


_l = logging.getLogger(__name__)


class SeedTriage:
    def __init__(
            self, oss_fuzz_target: OSSFuzzProject, harness_name: str, harness_filepath: Path,
            benign_seeds_dir: Path, crash_seeds_dir: Path
    ):
        # self._runner_path: Path = Path(run_script_path).resolve().absolute()
        self.harness_filepath = harness_filepath
        self.benign_seeds_dir = benign_seeds_dir
        self.crash_seeds_dir = crash_seeds_dir
        # project_yaml = os.path.join(self._runner_path.parent, "project.yaml")
        # self.project = yaml.safe_load(open(project_yaml))
        self.harness_name = harness_name
        # self.target_root = target_root
        self.oss_fuzz_target = oss_fuzz_target
        # self._extract_sanitizer_string()
        # self._extract_harness_name()
        assert self.harness_name

    # def _extract_sanitizer_string(self):
    #     sanitizers = self.project.get("sanitizers")
    #     sanitizer_strings = []
    #     for sanitizer_id, sanitizer_string in sanitizers.items():
    #         sanitizer_strings.append(sanitizer_string)
    #     self.sanitizer_strings = sanitizer_strings

    # def _extract_harness_name(self):
    #     harnesses = self.project.get("harnesses")
    #     _l.debug(f"harnesses is {harnesses}")
    #     for harness_id, harness in harnesses.items():
    #         _l.debug(f"harness in {harness}")
    #         _l.debug(f"self.harness_filepath is {self.harness_filepath}")
    #         if str(self.harness_filepath).endswith(harness["source"]):
    #             self.harness_name = harness["name"]
    #             return

    def generates_alerts(self, generated_input: Path) -> Path:
        _l.debug(f"generated_input is {generated_input}")
        random_filename = "".join(
                 random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
        crashing, result_msg = run_crash_input(self.oss_fuzz_target, self.harness_name, generated_input)
        if crashing:
            crash_path = os.path.join(self.crash_seeds_dir, f"{random_filename}.bin")
            shutil.copy(generated_input, crash_path)
            return crash_path
        else:
            benign_path = os.path.join(self.benign_seeds_dir, f"{random_filename}.bin")
            shutil.copy(generated_input, benign_path)
            return benign_path
         
        # with WorkDirContext(self._runner_path.parent):
        #     try:
        #         _l.debug(f"generated seed path is {generated_input}")
        #         p = run(
        #             [str(self._runner_path), "-x", "run_pov", str(generated_input), self.harness_name],
        #             capture_output=True,
        #             text=True,
        #             errors="ignore",
        #         )
        #         _l.debug(f"cmd is {[self._runner_path, 'run_pov', generated_input, self.harness_name]}")
        #         # get the return code from self._runner_path.parent/out/output, note that self._runner_path is absolute during initialization
        #         output_dir = os.path.join(self._runner_path.parent, "out", "output")
        #         latest_mtime = 0
        #         latest_folder = ""
        #         for folder in os.listdir(os.path.join(output_dir)):
        #             folder_path = os.path.join(output_dir, folder)
        #             if os.path.isdir(folder_path):
        #                 mtime = os.stat(folder_path).st_mtime
        #                 if mtime > latest_mtime:
        #                     latest_mtime = mtime
        #                     latest_folder = folder
        #         with open(os.path.join(output_dir, latest_folder, "exitcode")) as f:
        #             returncode = int(f.read())
        #         with open(os.path.join(output_dir, latest_folder, "stdout.log")) as f:
        #             stdout = f.read()
        #         with open(os.path.join(output_dir, latest_folder, "stderr.log")) as f:
        #             stderr = f.read()
        #         random_filename = "".join(
        #             random.choice(string.ascii_letters + string.digits) for _ in range(10)
        #         )
        #         if returncode == 0:
        #             # check stderr and stdout to see if sanitizer string is present
        #             _l.debug(f"saniter string is {self.sanitizer_strings}")
        #             for san_str in self.sanitizer_strings:
        #                 if san_str in stdout or san_str in stderr:
        #                     _l.debug(
        #                         f"Sanitizer was triggered with returncode {returncode} and sanitizer string {san_str}")
        #                     crash_path = os.path.join(self.crash_seeds_dir, f"{random_filename}.bin")
        #                     shutil.copy(generated_input, crash_path)
        #                     _l.debug(
        #                         f"generated crashing seed file {generated_input} is copied to {self.crash_seeds_dir}")
        #                     return Path(crash_path)
        #             # _l.debug(f"STDOUT\n\n{stdout}\n\n")
        #             # _l.debug(f"STDERR\n\n{stderr}\n\n")
        #             benign_path_by_harness = os.path.join(self.benign_seeds_dir, self.harness_name)
        #
        #             Path(benign_path_by_harness).mkdir(parents=True, exist_ok=True)
        #             benign_path = os.path.join(benign_path_by_harness, f"{random_filename}.bin")
        #             shutil.copy(generated_input, benign_path)
        #             _l.debug(
        #                 f"run_pov evaluation on {generated_input} passed with returncode {returncode} and it is a benign seed")
        #
        #             return Path(benign_path)
        #         else:
        #             _l.debug(f"STDOUT\n\n{stdout}\n\n")
        #             _l.debug(f"STDERR\n\n{stderr}\n\n")
        #             # if return code is not 0, then there is an internal error that prevented the evaluation from running
        #             _l.debug(f"run_pov evaluation failed with internal error, returncode {returncode}")
        #             return 1
        #
        #     except Exception as e:
        #         # if an exception is raised, then the evaluation failed
        #         _l.debug(f"Process failed with internal error, error message: {str(e)}")
        #         # _l.debug(f"STDOUT\n\n{e.stdout}\n\n")
        #         # _l.debug(f"STDERR\n\n{e.stderr}\n\n")
        #         return 1
