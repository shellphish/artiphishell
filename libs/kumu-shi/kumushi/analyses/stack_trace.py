from pathlib import Path
import json
import yaml
import logging

from kumushi.data.program import Program
from kumushi.data.poi import PoI, PoICluster, PoISource, CodeFunction
from shellphish_crs_utils.models import POIReport, FunctionIndex, CallTraceEntry
from .analysis import Analysis, AnalysisWeight

_l = logging.getLogger(__name__)


class StackTraceAnalysis(Analysis):
    NAME = "stack_trace"
    ANALYSIS_WEIGHT = AnalysisWeight.WEIGHTLESS

    def _analyze(self):
        main_stack = self.program.poi_report.stack_traces.get('main', None)
        clusters = []
        if main_stack:
            crash_stack_pois = main_stack.call_locations
            pois = self._generate_pois(crash_stack_pois, PoISource.STACK_TRACE)
            clusters = [PoICluster.from_pois([p], source=PoISource.STACK_TRACE) for p in pois]
        else:
            _l.critical(f"No main stack trace found in POI report.")

        free_stack = self.program.poi_report.stack_traces.get('free', None)
        if free_stack:
            free_stack_pois = free_stack.call_locations
            free_pois = self._generate_pois(free_stack_pois, PoISource.FREE_STACK)
            clusters += [PoICluster.from_pois([p], source=PoISource.FREE_STACK) for p in free_pois]

        return clusters

    def _generate_pois(self, pois: list[CallTraceEntry], poi_type: PoISource) -> list[PoI]:
        collect_pois = []
        for raw_poi in pois:
            source_location = raw_poi.source_location
            if source_location is None:
                continue
            if not source_location.focus_repo_relative_path:
                continue

            key_index = source_location.function_index_key
            if key_index is None:
                _l.info(f"Function {source_location.function_name} at {source_location.file_name} has no function index")
                continue
            crash_line_num = source_location.line_number
            crash_line = source_location.line_text
            function = self.program.code._function_resolver.get(key_index)
            if function is None:
                _l.info(f"Function {source_location.function_name} not found in code")
                continue
            raw_report = self.program.poi_report.additional_information.get("asan_report_data", None).get("cleaned_report",
                                                                                                       None)
            code_function = CodeFunction(name=function.funcname, start_line=function.start_line, end_line=function.end_line,
                                         file_path=function.focus_repo_relative_path, code=function.code,
                                         global_vars=function.global_variables)
            collect_pois.append(
                PoI(function=code_function, crash_line_num=crash_line_num, crash_line=crash_line,
                    sources=[poi_type], report=raw_report)
            )
        return collect_pois
