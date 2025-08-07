from typing import Optional, List, Any, Dict
import logging
import re
import json
import os
from pathlib import Path
from .asan_parser import AsanParser
from .kasan_parser import KasanParser
from .diff_parser import DiffParser
from .backtrace_analyzer import analyze_backtrace_report
from .report_type import ReportType
from ..data import ProgramPOI, ProgramInfo, InvarianceReport
from ..utils import llm_cost

_l = logging.getLogger(__name__)


class ReportAnalyzer:
    def __init__(
        self,
        report: Any,
        report_type: Optional[ReportType] = None,
        prog_info: Optional[ProgramInfo] = None,
        pois: List[ProgramPOI] = None,
        crashing_commit: Optional[str] = None,
        indices_by_commits: Optional[Path] = None,
        changed_func_by_commits: Optional[Path] = None,
        function_indices: Optional[Path] = None,
        func_json_dir: Optional[Path] = None,
    ):
        self._report = report
        self._prog_info = prog_info
        self._pois = pois or []
        self.cost = 0.0

        self._crashing_commit = crashing_commit

        self.report_type = report_type
        self.new_pois: List[ProgramPOI] = []

        self.indices_by_commits = indices_by_commits
        self.changed_func_by_commits = changed_func_by_commits
        self.function_indices = function_indices
        self.func_json_dir = func_json_dir

        self.sanitizer_string = None
        ran_commit_analysis = False
        if self._crashing_commit:
            ran_commit_analysis = True
            _l.debug(f"Doing analysis on the diff")
            self.report_type = ReportType.DIFF
            self.analyze()
            self.report_type = report_type        


        if ran_commit_analysis and ((self.report_type is None) or self.report_type == ReportType.DIFF):
            # early exit, we already did the commit analysis
            return 
        
        # only executes if we did not already run crashing commit in a None scenario
        if self.report_type is None:
            self.report_type = self._report_type_from_report(report)
            
        # TODO: we should not do this, but fix it after the submission
        self._pois = self.new_pois
        self.new_pois = []
        _l.debug(f"Doing analysis again")
        self.analyze()

    @staticmethod
    def _report_type_from_report(report) -> ReportType:
        kasan_pattern = re.compile(r"syz|kasan|kmsan|kernel", re.IGNORECASE)
        # TODO: Find a bettern way to figure out ASAN report
        asan_err_strs = re.findall(r"==\d+==ERROR:", report)
        asan_warn_strs = re.findall(r"==\d+==WARNING:", report)

        if asan_err_strs or asan_warn_strs:
            return ReportType.ASAN
        elif kasan_pattern.search(report):
            return ReportType.KASAN
        else:
            try:
                report = json.loads(report.replace("'", '"'))
                if "pois" in report:
                    return ReportType.BACKTRACE
            except Exception as e:
                _l.warning(f"Encountered error while trying to parse a report: {e}... assuming backtrace report.")

            return ReportType.BACKTRACE

    def analyze(self):
        _l.debug(f"Report type is {self.report_type}")
        if self.report_type == ReportType.ASAN:
            self._analyze_asan_report()
        elif self.report_type == ReportType.KASAN:
            self._analyze_kasan_report()
        elif self.report_type == ReportType.BACKTRACE:
            self._analyze_backtrace_report()
        elif self.report_type == ReportType.INVARIANCE:
            self._analyze_invariance_report()
        elif self.report_type == ReportType.DIFF:
            self._filter_pois_from_crash_commit()
        else:
            # _l.warning(f"Unknown report type: {self.report_type}")
            self.new_report = None

    def _filter_pois_from_crash_commit(self):
        if not self._crashing_commit:
            _l.debug("You do not provide a crash commit id.")
            return None
        self.new_pois = []
        #       indices_by_commits: Path,
        # changed_func_json_dir_by_commits: Path,
        # indices: Path,
        # func_json_dir: Path,
        # for poi in self._pois:
        diff_parser = DiffParser(
            self._prog_info,
            crash_commit=self._crashing_commit,
            indices_by_commits=self.indices_by_commits,
            changed_func_json_dir_by_commits=self.changed_func_by_commits,
            indices=self.function_indices,
            func_json_dir=self.func_json_dir,
        )

        git_diff_pois = diff_parser.retrieve_pois()
        # We just use the same report for poi we generate from crash commit
        first_poi = self._pois[0]
        if len(self._pois) == 1 and first_poi.file == "." and first_poi.function == None:
            self._pois = []
        report = self._pois[0].report
        stack_trace_only = []
        intersections = []
        intersections_functions = []
        for poi in self._pois:
            found = False
            for commit_poi in git_diff_pois:
                if poi.function == commit_poi.function:
                    found = True
                    poi.git_diff = commit_poi.git_diff
                    intersections.append(poi)
                    intersections_functions.append(poi.function)
                    break
            if not found:
                stack_trace_only.append(poi)
        commit_change_only = []
        for poi in git_diff_pois:
            if poi.function not in intersections_functions:
                poi.report = report
                commit_change_only.append(poi)
        if len(intersections) + len(commit_change_only) > 6:
            self.new_pois = intersections + stack_trace_only
        else:
            self.new_pois = intersections + commit_change_only + stack_trace_only

    def _analyze_asan_report(self):
        aparser = AsanParser(self._report)
        # FIXME: There is some error in extract_sanitizer_string in ASAN
        self.sanitizer_string = aparser.extract_sanitizer_string()

        new_pois_dict = aparser.extract_function_info()
        self._construct_pois_from_dict(new_pois_dict)

    def _analyze_kasan_report(self):
        kparser = KasanParser(self._report)
        self.sanitizer_string = kparser.extract_sanitizer_string()
        new_pois_dict = kparser.extract_function_info()
        self._construct_pois_from_dict(new_pois_dict)

    def _analyze_backtrace_report(self):
        if not self._pois or self._prog_info is None:
            # _l.warning("You must provide a PoI and ProgramInfo to use backtrace report parsing!")
            return

       
        new_report, prompt_tokens, completion_tokens = analyze_backtrace_report(
            [poi for poi in self._pois], self._prog_info
        )
        # default agentlib llm is gpt-4-turbo
        cost = llm_cost("oai-gpt-4-turbo", prompt_tokens, completion_tokens)
        _l.debug(
            f"use {prompt_tokens} input tokens, produce {completion_tokens} output tokens \n the cost for report analyzer is {cost}"
        )
        self.cost = cost
        for poi in self._pois:
            poi.report = new_report
            self.new_pois.append(poi)

    def _analyze_invariance_report(self):
        if not isinstance(self._report, InvarianceReport):
            raise ValueError("Invariance report must be provided for invariance report analysis.")
        #FIXME: cross reference diff pois with invariance pois 
        self.new_pois = [self._report.to_poi(self._prog_info, self.function_indices, self.func_json_dir)]

    def _construct_pois_from_dict(self, new_pois_dict):
        new_pois = []

        for poi in new_pois_dict:
            if os.path.isabs(poi["relative_file_path"]):
                fpath = poi["relative_file_path"][1:]
            else:
                fpath = poi["relative_file_path"]
            new_pois.append(
                ProgramPOI(
                    fpath,
                    poi["function"],
                    int(poi["line_number"]),
                    report=self._report or "",
                )
            )
        self.new_pois = new_pois

    def pois_to_aicc_format(self) -> dict:
        if not self.new_pois:
            return {}

        return {
            "sanitizer_string": self.sanitizer_string,
            "pois": [poi.to_aicc_format() for poi in self.new_pois],
            "harness_id": "id_1",  # We assume for oss-fuzz target the harness_id always id_1
        }
