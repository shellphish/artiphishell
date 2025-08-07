import logging
import typing
from pathlib import Path
from typing import List, Optional, Tuple
import tempfile
import subprocess
import os
import shutil

import git
from patchery.data.program_info import ProgramInfo
from patchery.utils import WorkDirContext
from patchery.data.aicc.aicc_executor import AICCExecutor

if typing.TYPE_CHECKING:
    from patchery.data import ProgramPOI, Executor
    from patchery import ProgramInput

AICC_DATA_DIR = Path(__file__).parent.absolute()
AICC_DOCKER_DATA_DIR = AICC_DATA_DIR / "docker_data"
_l = logging.getLogger(__name__)


class AICCProgramInfo(ProgramInfo):
    def __init__(
        self,
        source_root: Path,
        lang: str,
        run_script: Path,
        compile_name: str = None,
        executor: Optional["AICCExecutor"] = None,
        benign_inputs: List["ProgramInput"] = None,
        harness_id: str = None,
        harness_name: str = None,
        sanitizer_string: str = None,
        alerting_inputs: List["ProgramInput"] = None,
        has_history: bool = True,
        has_reproducer=False,
        c_reproducer_folder: Path = None,
        is_kernel: bool = False,
        kernel_image_dir: Path = None,
    ):
        if executor is None:
            executor = AICCExecutor(run_script / "run.sh", harness_name, sanitizer_string, harness_id=harness_id)

        super().__init__(
            source_root,
            lang,
            executor=executor,
            benign_inputs=benign_inputs,
            alerting_inputs=alerting_inputs,
            has_history=has_history,
            has_reproducer=has_reproducer,
            is_kernel=is_kernel,
        )
        self._run_script = Path(run_script).resolve().absolute()
        self._compile_name = compile_name
        self._cp_copy_dir = None #self._create_initial_copy_dir(run_script)

        self.harness_id = harness_id
        self.harness_name = harness_name
        self.sanitizer_string = sanitizer_string

        self.c_reproducer_folder = c_reproducer_folder
        self.kernel_image_dir = kernel_image_dir

        # program compiling related variables
        self._patchery_docker_env_file = AICC_DOCKER_DATA_DIR / ".env.docker"
        self._docker_env_dst = self._run_script / ".env.docker"
        self._ccache_binary_file = AICC_DOCKER_DATA_DIR / "ccache"
        self._work_dir = self._run_script / "work"

    def setup_program(self):
        assert self._patchery_docker_env_file.exists(), f"Missing Docker environment file: {self._patchery_docker_env_file}"
        assert self._ccache_binary_file.exists(), f"Missing ccache binary file: {self._ccache_binary_file}"

        # copy the ccache binary to the run_script
        shutil.copy(self._ccache_binary_file, self._work_dir)

        # copy the compile script to the run_script
        shutil.copy(AICC_DOCKER_DATA_DIR / "compile", self._work_dir / "compile")
        shutil.copy(AICC_DOCKER_DATA_DIR / "compile++", self._work_dir / "compile++")
        
        # copy the .env.docker file to dst 
        if self._docker_env_dst.exists():
            self._docker_env_dst.unlink()
        shutil.copy(self._patchery_docker_env_file, self._docker_env_dst)
        
        # symlink the clang compiler to ccache
        #subprocess.run(["ln", "-s", "/work/ccache", str(self._run_script / "work/clang")])
        #subprocess.run(["ln", "-s", "/work/ccache", str(self._run_script / "work/clang++")])

        compile_cache_dir = self._run_script / "work/compiler_cache"
        if compile_cache_dir.exists():
            shutil.rmtree(compile_cache_dir)
        compile_cache_dir.mkdir()

    def _abandon_ccache(self):
        # clear the dst_env file to have nothing in it
        if self._docker_env_dst.exists():
            with open(self._docker_env_dst, "w") as f:
                f.write("")

    def _has_ccache_failure(self, stdout: str, stderr: str) -> bool:
        failure_strings = [
            "/work/clang: No such file or directory",
            "/work/clang++: No such file or directory",
            '"/work/clang" not found',
            '"/work/clang++" not found',
            "/work/clang not found",
            "/work/clang++ not found",
            "clang not found",
            "clang++ not found",
            'Could not find compiler "clang" in PATH',
            'Could not find compiler "clang++" in PATH',
            "ccache: error:",
            'Could not find compiler',
        ]
        for failure_string in failure_strings:
            if failure_string in stdout or failure_string in stderr:
                return True
            
        return False

    def _compile_core(self, patch_path: Optional[Path] = None, **kwargs) -> Tuple[bool, str]:
        if patch_path is not None:
            patch_path = Path(patch_path).absolute()
        source_root_abs = Path(self.source_root).resolve().absolute()
        runner_folder_abs = Path(self._run_script).resolve().absolute()

        with WorkDirContext(self._run_script):
            compile_cmd = "./run.sh build "
            if patch_path is not None:
                compile_cmd += f"{patch_path}"
                if self._compile_name is not None:
                    compile_cmd += f" {self._compile_name}"
            
            _l.debug(f"Running compilation now with command: %s", compile_cmd)
            try:
                proc = subprocess.run(compile_cmd.split(), capture_output=True, text=True)
                # get the return code from self._run_script/out/output
                output_dir = os.path.join(runner_folder_abs, "out", "output")
                latest_mtime = 0
                latest_folder = ""
                for folder in os.listdir(os.path.join(output_dir)):
                    folder_path = os.path.join(output_dir, folder)
                    if os.path.isdir(folder_path):
                        mtime = os.stat(folder_path).st_mtime
                        if mtime > latest_mtime:
                            latest_mtime = mtime
                            latest_folder = folder

                # read the AICC output
                with open(os.path.join(output_dir, latest_folder, "exitcode")) as f:
                    returncode = int(f.read())
                with open(os.path.join(output_dir, latest_folder, "stdout.log")) as f:
                    stdout = f.read()
                with open(os.path.join(output_dir, latest_folder, "stderr.log")) as f:
                    stderr = f.read()

                # sanity check ccache
                if self._has_ccache_failure(stdout, stderr):
                    _l.critical(f"A ccache failure was detected, abandoning ccache for this program!")
                    self._abandon_ccache()

                # if everything was empty, check the real procs outout
                if not stdout:
                    _l.debug(f"stdout was empty, checking real proc output")
                    stdout = proc.stdout
                if not stderr:
                    _l.debug(f"stderr was empty, checking real proc stderr")
                    stderr = proc.stderr

                if returncode != 0:
                    _l.debug(f"returncode {returncode}\n")
                    _l.debug(f"stdout {stdout}\n")
                    _l.debug(f"stderr {stderr}\n")
                    passed = False
                    reason = stderr
                    if self.lang == "java":
                        reason = ""
                        lines = stdout.replace("\\n", "\n").split("\n")
                        for line in lines:
                            if line.startswith(" [ERROR]"):
                                reason += line + "\n"
                else:
                    passed = True
                    reason = "Successful compilation."
            except Exception as e:
                passed = False
                reason = f"Internal compilation error with exception: {e}"

            repo = git.Repo(source_root_abs)
            repo.git.reset("--hard")
            return passed, reason

    @staticmethod
    def rsync_copy_dir(source: Path, dest: Path):
        cmd = ["rsync", "-raz", "--delete", str(source) + "/", str(dest) + "/"]
        subprocess.run(cmd, check=True)
        return True

    @staticmethod
    def _create_initial_copy_dir(dir_path: Path):
        tmp_dir = Path(tempfile.mkdtemp())
        _l.debug(f"Copying {dir_path} to {tmp_dir}")
        AICCProgramInfo.rsync_copy_dir(dir_path, tmp_dir)
        return tmp_dir
