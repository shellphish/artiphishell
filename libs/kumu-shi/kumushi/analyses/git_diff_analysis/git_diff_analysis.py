import logging

from .diff_parser import DiffParser
from ..analysis import Analysis, AnalysisWeight
from shellphish_crs_utils.function_resolver import LocalFunctionResolver

_l = logging.getLogger(__name__)


class GitDiffAnalysis(Analysis):
    NAME = "git_diff"
    ANALYSIS_WEIGHT = AnalysisWeight.WEIGHTLESS
    TIMEOUT = 10*60 # Default 10 minutes timeout

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.has_git_info = bool(self.program.delta_mode)
        self._program = self.program
        self.local_run = self.program.local_run
        if self.has_git_info:
            self.commit_function_resolver = LocalFunctionResolver(
                str(self.program.indices_by_commit_path),
                str(self.program.functions_by_commit_jsons_dir),
            )
            self.project_name = self.program.poi_report.project_name

    def _analyze(self):
        if not self.has_git_info:
            return []
        return DiffParser(
            self._program,
            self.commit_function_resolver,
            self.local_run,
            self.project_name,
        ).retrieve_pois()
