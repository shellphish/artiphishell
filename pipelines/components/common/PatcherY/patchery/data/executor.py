import logging

from patchery.data.program_trace import ProgramTrace
from patchery.data.program_input import ProgramInput
from patchery.data.program_alert import ProgramExitType

_l = logging.getLogger(__name__)


class Executor:
    def __init__(self, *args, **kwargs):
        pass

    def trace(self, prog_input: ProgramInput) -> ProgramTrace:
        raise NotImplementedError()

    def generates_alerts(self, prog_input: ProgramInput, **kwargs) -> bool:
        raise NotImplementedError()

    def check_functionality(self) -> ProgramExitType:
        raise NotImplementedError()
