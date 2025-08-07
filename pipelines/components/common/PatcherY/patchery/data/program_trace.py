from typing import List

from .program_input import ProgramInput
from .program_alert import ProgramAlert


class ProgramTrace:
    def __init__(self, prog_input: ProgramInput, backtrace=None, alerts: List[ProgramAlert] = None):
        self.prog_input = prog_input
        self.backtrace = backtrace
        self.alerts = alerts or []
