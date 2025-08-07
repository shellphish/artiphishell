import logging
import os
import subprocess
import traceback
from pathlib import Path

from .base_verification_pass import BaseVerificationPass
from patchery.data.aicc import AICCProgramInfo
from ...data import ProgramExitType
from ...utils import WorkDirContext

_l = logging.getLogger(__name__)


class SyzCallerVerificationPass(BaseVerificationPass):
    def __init__(self, *args, kernel_pass=True, base_prog_class=AICCProgramInfo, **kwargs):
        super().__init__(*args, kernel_pass=kernel_pass, base_prog_class=base_prog_class, **kwargs)

    def _verify(self):
        self._prog_info: AICCProgramInfo
        sanitizer_string = self._prog_info.sanitizer_string
        reasoning = None
        passed = True
        for c_reproducer_fp in os.listdir(self._prog_info.c_reproducer_folder):
            if not os.path.isfile(c_reproducer_fp) and os.access(c_reproducer_fp, os.R_OK):
                _l.debug(f"❔ Skipping : {c_reproducer_fp} is not a file or not readable")
                continue
            try:
                _l.debug(f"❔ Checking c reproducer: {c_reproducer_fp}")
                exit_type = self.run_c_reproducer(
                    Path(os.path.join(self._prog_info.c_reproducer_folder, c_reproducer_fp)).resolve().absolute(),
                    self._prog_info.kernel_image_dir,
                    sanitizer_string,
                )
                if exit_type == ProgramExitType.TRIGGERED:
                    # TODO: make a better reason and resuse the old alert
                    return False, "C reproducer crash triggered after patching"
                elif exit_type == ProgramExitType.INTERNAL_ERROR:
                    reasoning = "Skipped because internal error occurred during reproducer crash check"
                    passed = True
            except Exception as e:
                _l.debug(f"❌  Error occurred during reproducer crash check: {e}", exc_info=True)
                continue

        return passed, reasoning

    def run_c_reproducer(self, c_reproducer: Path, kernel_image: Path, sanitizer_string: str) -> ProgramExitType:
        kernelFN = kernel_image

        # Delete any pre-existing repro file
        vulnFN = "./repro"
        if os.path.isfile(vulnFN):
            os.remove(vulnFN)

        # Try build the c_reproducer
        with WorkDirContext(c_reproducer.parent):
            try:
                result = subprocess.run(
                    ["gcc", str(Path(c_reproducer).resolve().absolute()), "-o", "repro"],
                    capture_output=True,
                    timeout=100,
                )
                if result.returncode != 0:
                    print("gcc failed to compile the cReprocuder")
                    print("gcc stdout: " + result.stdout.decode("utf-8"))
                    print("gcc stderr: " + result.stderr.decode("utf-8"))
                    return ProgramExitType.INTERNAL_ERROR
                result = subprocess.run(["chmod", "+x", "./repro"], capture_output=True, timeout=100)
                if result.returncode != 0:
                    print("chmod failed to make the cReprocuder executable")
                    print("chmod stdout: " + result.stdout.decode("utf-8"))
                    print("chmod stderr: " + result.stderr.decode("utf-8"))
                    return ProgramExitType.INTERNAL_ERROR
            except subprocess.TimeoutExpired as timeErr:
                print("Timeout in gcc or chmod")
                print("gcc stdout: " + timeErr.stdout.decode("utf-8"))
                print("gcc stderr: " + timeErr.stderr.decode("utf-8"))
                return ProgramExitType.INTERNAL_ERROR
            except Exception as e:
                print(f"Error occurred during c reproducer compilation: {e}")
                return ProgramExitType.INTERNAL_ERROR
            stdoutData = ""
            stderrData = ""
            try:
                result = subprocess.run(
                    [
                        "virtme-run",
                        "--verbose",
                        "--show-boot-console",
                        "--kimg",
                        str(Path(kernelFN).resolve().absolute()),
                        "--memory",
                        "2G",
                        "--mods=auto",
                        "--script-exec",
                        str(Path("./repro").resolve().absolute()),
                    ],
                    capture_output=True,
                    timeout=360,
                )
                # Get the stdout data as a string
                stdoutData = result.stdout.decode("utf-8")
                # Get the stderr data as a string
                stderrData = result.stderr.decode("utf-8")
                if result.returncode != 0:
                    _l.debug("virtme-run failed to run the cReprocuder")
                    _l.debug("virtme-run stdout: " + stdoutData)
                    _l.debug("virtme-run stderr: " + stderrData)
                    if os.path.isfile(vulnFN):
                        os.remove(vulnFN)
                    return ProgramExitType.INTERNAL_ERROR
                # _l.debug(f"stdout: {stdoutData}")
                # _l.debug(f"stderr: {stderrData}")
                # with open("virtme-run-stdout.txt", "w") as f:
                #     f.write(stdoutData)
                # with open("virtme-run-stderr.txt", "w") as f:
                #     f.write(stderrData)
                if os.path.isfile(vulnFN):
                    os.remove(vulnFN)

            except subprocess.TimeoutExpired as timeErr:
                print("WARNING: Timeout in virtme-run")
                os.system("killall /usr/bin/qemu-system-x86_64")

                # Try to get the stdout and stderr data as a string
                if timeErr.stdout is not None:
                    stdoutData = timeErr.stdout.decode("utf-8")
                if timeErr.stderr is not None:
                    stderrData = timeErr.stderr.decode("utf-8")
                # _l.debug(f"stdout: {stdoutData}")
                # _l.debug(f"stderr: {stderrData}")
                # with open("virtme-run-stdout.txt", "w") as f:
                #     f.write(stdoutData)
                # with open("virtme-run-stderr.txt", "w") as f:
                #     f.write(stderrData)
                if os.path.isfile(vulnFN):
                    os.remove(vulnFN)
                # we check the stdout and stderr for the sanitizer string, even for a timeout, since some c_reproducers may contain an infinite loop
            except Exception:
                print("Unexpected Exception:\n")
                traceback.print_exc()
                _l.warning("Unexpected exception occurred.", exc_info=True)
                if os.path.isfile(vulnFN):
                    os.remove(vulnFN)
                return ProgramExitType.INTERNAL_ERROR
        if sanitizer_string in stdoutData or sanitizer_string in stderrData:
            return ProgramExitType.TRIGGERED
        else:
            return ProgramExitType.NORMAL
