from enum import IntEnum


class ProgramExitType(IntEnum):
    NORMAL = 0  # normal execution, no alert
    TRIGGERED = 1  # alert was triggered or functionality check failed
    INTERNAL_ERROR = 2  # program crashed, unexpected behavior


class ProgramAlert:
    def __init__(self, exit_code: ProgramExitType, stdout: str, stderr: str):
        self._exit_type = exit_code
        self._stdout = stdout
        self._stderr = stderr

    @property
    def is_alert(self):
        return self._exit_type == ProgramExitType.TRIGGERED

    @property
    def stdout(self):
        return self._stdout

    @property
    def stderr(self):
        return self._stderr
