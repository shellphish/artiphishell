import logging

from kumushi.data import ProgramInput, PoI, PoICluster
from kumushi.aixcc import AICCProgram

_l = logging.getLogger(__name__)

class AbstractTracer:
    def __init__(self, program: AICCProgram):
        self.program = program
        self.is_instrumented = False

    def instrument(self, **kwargs):
        self.is_instrumented = True

    def trace(self, program_input: ProgramInput, **kwargs) -> list[PoI]:
        """
        Trace the given inputs and return a list of Points of Interest (PoIs).
        This method should be implemented by subclasses.
        """
        if not self.is_instrumented:
            self.instrument(**kwargs)

        return self._trace(program_input, **kwargs)

    def _trace(self, program_input: ProgramInput, **kwargs) -> list[PoI]:
        raise NotImplementedError()

    def trace_many(self, program_inputs: list[ProgramInput], **kwargs) -> dict[ProgramInput,list[PoI]]:
        self.instrument(**kwargs)
        traces = {}
        for program_input in program_inputs:
            try:
                traces[program_input] = self.trace(program_input, **kwargs)
            except Exception as e:
                _l.critical(f"Failed to trace input %s: %s", program_input, e)

        return traces