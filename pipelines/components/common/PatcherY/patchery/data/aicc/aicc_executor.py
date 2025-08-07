import logging
from pathlib import Path
from signal import Signals
from os import access, X_OK
from tempfile import NamedTemporaryFile
from subprocess import run, PIPE, TimeoutExpired, CalledProcessError
import typing
import os

from ..executor import Executor
from ...utils import WorkDirContext
from patchery.data.program_alert import ProgramAlert, ProgramExitType

if typing.TYPE_CHECKING:
    from patchery.data.program_trace import ProgramTrace
    from patchery.data.program_input import ProgramInput

_l = logging.getLogger(__name__)


class AICCExecutor(Executor):
    def __init__(
        self, run_script_path: Path, harness_name: str, sanitizer_string: str, harness_id: str = None, **kwargs
    ):
        self._runner_path: Path = Path(run_script_path).resolve().absolute()
        self.harness_name = harness_name
        self.harness_id = harness_id
        self.sanitizer_string = sanitizer_string
        super().__init__(**kwargs)

    def trace(self, prog_input: "ProgramInput") -> "ProgramTrace":
        # TODO: implement this
        return None

    def generates_alerts(self, prog_input: "ProgramInput") -> ProgramExitType:
        with NamedTemporaryFile(delete=False) as input_file:
            input_file.write(prog_input.data)
            input_file.close()

            alert = None
            p = None
            with WorkDirContext(self._runner_path.parent):
                _l.debug(f"Executing run_pov on harness_name=%s (harness_id=%s)", self.harness_name, self.harness_id)
                try:
                    p = run(
                        [self._runner_path, "run_pov", input_file.name, self.harness_name],
                        capture_output=True,
                        text=True,
                        errors="ignore",
                    )
                    _l.debug(f"cmd is {[self._runner_path, 'run_pov', input_file.name , self.harness_name]}")
                    # get the return code from self._runner_path.parent/out/output, note that self._runner_path is absolute during initialization
                    output_dir = os.path.join(self._runner_path.parent, "out", "output")
                    latest_mtime = 0
                    latest_folder = ""
                    for folder in os.listdir(os.path.join(output_dir)):
                        folder_path = os.path.join(output_dir, folder)
                        if os.path.isdir(folder_path):
                            mtime = os.stat(folder_path).st_mtime
                            if mtime > latest_mtime:
                                latest_mtime = mtime
                                latest_folder = folder
                    with open(os.path.join(output_dir, latest_folder, "exitcode")) as f:
                        returncode = int(f.read())
                    with open(os.path.join(output_dir, latest_folder, "stdout.log")) as f:
                        stdout = f.read()
                    with open(os.path.join(output_dir, latest_folder, "stderr.log")) as f:
                        stderr = f.read()
                    if returncode == 0:
                        # check stderr and stdout to see if sanitizer string is present
                        _l.debug(f"saniter string is {self.sanitizer_string}")
                        if self.sanitizer_string in stdout or self.sanitizer_string in stderr:
                            _l.debug(f"Sanitizer was triggered with returncode {returncode}")
                            # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                            # _l.debug(f"STDERR\n\n{stderr}\n\n")
                            alert = ProgramAlert(ProgramExitType.TRIGGERED, stdout, stderr)
                        # if sanitizer string is not present, then it was not triggered
                        else:
                            _l.debug(f"Sanitizer was *NOT* triggered, returncode {returncode}")
                            # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                            # _l.debug(f"STDERR\n\n{stderr}\n\n")
                            alert = ProgramAlert(ProgramExitType.NORMAL, stdout, stderr)
                    else:
                        # if return code is not 0, then there is an internal error that prevented the evaluation from running
                        _l.debug(f"run_pov evaluation failed with internal error, returncode {returncode}")
                        # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                        # _l.debug(f"STDERR\n\n{stderr}\n\n")
                        alert = ProgramAlert(ProgramExitType.INTERNAL_ERROR, stdout, stderr)
                except Exception as e:
                    if p is not None:
                    # if an exception is raised, then the evaluation failed
                        _l.debug(f"Process failed with internal error {e}, returncode {p.returncode}")
                    # _l.debug(f"STDOUT\n\n{e.stdout}\n\n")
                    # _l.debug(f"STDERR\n\n{e.stderr}\n\n")
                    error_msg = "internal error"
                    alert = ProgramAlert(ProgramExitType.INTERNAL_ERROR, "", error_msg)
        return alert._exit_type

    def check_functionality(self) -> ProgramExitType:
        alert = None
        with WorkDirContext(self._runner_path.parent):
            p = None
            try:
                p = run([self._runner_path, "run_tests"], capture_output=True, text=True)
                # get the return code from self._runner_path.parent/out/output, note that self._runner_path is absolute during initialization
                output_dir = os.path.join(self._runner_path.parent, "out", "output")
                latest_mtime = 0
                latest_folder = ""
                for folder in os.listdir(os.path.join(output_dir)):
                    folder_path = os.path.join(output_dir, folder)
                    if os.path.isdir(folder_path):
                        mtime = os.stat(folder_path).st_mtime
                        if mtime > latest_mtime:
                            latest_mtime = mtime
                            latest_folder = folder
                with open(os.path.join(output_dir, latest_folder, "exitcode")) as f:
                    returncode = int(f.read())
                with open(os.path.join(output_dir, latest_folder, "stdout.log")) as f:
                    stdout = f.read()
                with open(os.path.join(output_dir, latest_folder, "stderr.log")) as f:
                    stderr = f.read()
                if returncode == 0:
                    # check stderr and stdout to see if sanitizer string is present
                    _l.debug(f"run_tests evaluation passed, returncode {returncode}")
                    # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                    # _l.debug(f"STDERR\n\n{stderr}\n\n")
                    alert = ProgramAlert(ProgramExitType.NORMAL, stdout, stderr)
                elif returncode == 1:
                    # if return code is not 0, then there is an internal error that prevented the evaluation from running
                    _l.debug(f"run_tests Evaluation failed with internal error, returncode {returncode}")
                    # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                    # _l.debug(f"STDERR\n\n{stderr}\n\n")
                    alert = ProgramAlert(ProgramExitType.INTERNAL_ERROR, stdout, stderr)
                else:
                    _l.debug(f"run_tests Evaluation failed with code {returncode}")
                    # _l.debug(f"STDOUT\n\n{stdout}\n\n")
                    # _l.debug(f"STDERR\n\n{stderr}\n\n")
                    alert = ProgramAlert(ProgramExitType.TRIGGERED, stdout, stderr)
            except Exception as e:
                if p is not None:
                    # if an exception is raised, then the evaluation failed
                    _l.debug(f"Process failed with internal error {e} , returncode {p.returncode}")
                    
                # _l.debug(f"STDOUT\n\n{e.stdout}\n\n")
                # _l.debug(f"STDERR\n\n{e.stderr}\n\n")
                error_msg = "internal error"
                alert = ProgramAlert(ProgramExitType.INTERNAL_ERROR, "", error_msg)
        return alert._exit_type
