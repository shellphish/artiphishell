import logging

from kumushi.aixcc import AICCProgram
from kumushi.data import ProgramInput, PoI
from kumushi.tracing.abstract_tracer import AbstractTracer
from kumushi.tracing.smart_tracer import SmartCallTracer
from kumushi.tracing.dumb_tracer import DumbCallTracer
from itertools import chain
logging.getLogger("shellphish_crs_utils.function_resolver").setLevel(logging.ERROR)
_l = logging.getLogger(__name__)

class FlexibleTracer(AbstractTracer):
    """
    The FlexibleTracer is a tracer that attempts to use both a risky tracing style and then fallback to a safer one
    if the first fails.
    """
    def __init__(self, program: AICCProgram, prioritize_smart: bool = False, analysis_name: str | None = None):
        super().__init__(program)
        self._is_smart = prioritize_smart
        self._tracer = None
        self._analysis_name = analysis_name

    def _trace_core(self, program_inputs: list[ProgramInput], **kwargs) -> dict[ProgramInput, list[PoI]]:
        traces = {}
        failed = False
        if not program_inputs:
            _l.warning("No program inputs provided for tracing, returning empty traces.")
            return traces
        if not self._is_smart and "c" in str(self.program.language).lower():
            from kumushi.analyses.analysis import AnalysisTimeoutError
            try:
                _l.info("Using DumbCallTracer to trace for analysis '%s'...", self._analysis_name or "unknown")
                tracer = DumbCallTracer(self.program)
                traces = tracer.trace_many(program_inputs, **kwargs)
            # not sure whether to raise this timeout error
            # except Exception as AnalysisTimeoutError:
            #     _l.critical("DumbCallTracer timed out, kill the trace", exc_info=True)
            #     failed = True
            #     raise AnalysisTimeoutError
            except Exception as e:
                _l.critical("in analysis %s Failed to trace with DumbCallTracer, falling back to SmartCallTracer: %s",
                            self._analysis_name or "unknown", e, exc_info=True)
                failed = True

            all_traces = list(chain.from_iterable(traces.values())) if traces else []
            if not failed and not all_traces:
                _l.warning("No PoIs found with DumbCallTracer, attempting SmartCallTracer...")
                failed = True
        else:
            # TODO: support other languages if needed
            failed = True

        if failed:
            self._is_smart = True
            _l.info("Using SmartCallTracer to for analysis '%s'...", self._analysis_name or "unknown")
            tracer = SmartCallTracer(self.program)
            #FIXME: if rio tracer works, change it back to 200
            traces = tracer.trace_many(program_inputs, **kwargs)


        all_traces = list(chain.from_iterable(traces.values())) if traces else []
        if not all_traces:
            _l.error("No PoIs were found in the call trace! This is unexpected.")
            return {}

        return traces

    def trace_many(self, program_inputs: list[ProgramInput], **kwargs) -> dict[ProgramInput,list[PoI] | list[str]]:
        return self._trace_core(program_inputs, **kwargs)

    def trace(self, program_input: ProgramInput, **kwargs) -> list[PoI]:
        traces = self._trace_core([program_input], **kwargs)
        program_trace = traces.get(program_input, [])
        if not program_trace:
            _l.error("No PoIs were found in the call trace for the given input!")
            return []

        _l.info(f"Found {len(program_trace)} PoIs in the call trace!")
        return program_trace

    def instrument(self, **kwargs):
        self._tracer.instrument(**kwargs)

