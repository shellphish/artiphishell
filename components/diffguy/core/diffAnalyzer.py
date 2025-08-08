"""
DiffAnalyzer class for comparing two CodeQL databases.
"""
import os
import logging
from typing import Dict, List, Tuple, Any, Optional, Set
import sys
import yaml
import json


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import FILE_TEMPLATES, QUERY_PATHS, DIFFGUY_TIMEOUT
from core.utils import save_json, load_json, ensure_directories, function_resolve

from core.analyzer.funcAnalyzer import FunctionDiffAnalyzer
from core.analyzer.boundaryAnalyzer import BoundaryDiffAnalyzer
from core.analyzer.fileAnalyzer import FileDiffAnalyzer
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.function_resolver import FunctionResolver
from .project import Project

# Configure logging
logger = logging.getLogger(__name__)
class DiffAnalyzer:
    """A class for comparing two CodeQL databases."""

    def __init__(self, project_name: str, language: str,  id1: str, id2: str, query_path: str, save_path: str, diff_mode: str, run_mode: str = "remote"):

        self.name = project_name
        self.language = language
        self.id_before = id1
        self.id_after = id2

        if self.language == "c" or self.language == "c++":
            self.query_path = os.path.join(query_path, "c")
        if self.language == "jvm":
            self.query_path = os.path.join(query_path, "jvm")

        self.save_path = os.path.join(save_path, project_name)
        ensure_directories(self.save_path)
        self.diff_mode = diff_mode
        self.run_mode = run_mode

        self.load_project()
        self.function_diff_results = None
        self.boundary_diff_results = None
        self.file_diff_results = None
        self.file_diff_result_before_llm = None

        if self.run_mode == "remote":
            # index_path = os.environ.get("FULL_FUNCTIONS_INDEX")
            # jsons_path = os.environ.get("FULL_FUNCTIONS_JSONS_DIR")
            # self.solver = LocalFunctionResolver(index_path, jsons_path)
            self.solver = RemoteFunctionResolver(self.name, self.id_after)

        elif self.run_mode == "local":
            index_path = os.environ.get("FUNCTIONS_INDEX")
            jsons_path = os.environ.get("FUNCTIONS_JSONS_DIR")
            self.solver = LocalFunctionResolver(index_path, jsons_path)

        self.diffguy_report_path = os.path.join(self.save_path, FILE_TEMPLATES["diffguy_report"])

    def load_project(self) -> None:
        self.project_before = Project(self.name, "before", self.id_before, self.language, self.query_path, self.save_path)
        self.project_after = Project(self.name, "after", self.id_after, self.language, self.query_path, self.save_path)


    def run(self):
        if self.diff_mode == "function":
            self.function_diff()
        elif self.diff_mode == "boundary":
            self.boundary_diff()
        elif self.diff_mode == "file":
            self.file_diff()
        elif self.diff_mode == "all":
            self.function_diff()
            self.boundary_diff()
            self.file_diff()
            self.output_report()
        else:
            raise ValueError(f"Unknown diff mode: {self.diff_mode}")

    def function_diff(self):
        function_analyzer = FunctionDiffAnalyzer(self.name, self.project_before, self.project_after, self.language, self.query_path, self.save_path, self.solver)
        self.function_diff_results = function_analyzer.func_diff_result_list


    def boundary_diff(self):
        boundary_analyzer = BoundaryDiffAnalyzer(self.name, self.project_before, self.project_after, self.language, self.query_path, self.save_path, self.solver)
        self.boundary_diff_results = boundary_analyzer.boundary_diff_result_list


    def file_diff(self):
        file_analyzer = FileDiffAnalyzer(self.name, self.project_before, self.project_after, self.language, self.query_path, self.save_path, self.solver)
        self.file_diff_results = file_analyzer.file_diff_result_list

        # self.file_diff_result_before_llm = file_analyzer.file_diff_result_list_before_llm
        # import ipdb; ipdb.set_trace()

    def output_report(self):

        # union_T = function_resolve(list(self.function_diff_results | self.boundary_diff_results), self.language, self.solver)
        # import ipdb; ipdb.set_trace()
        # function_diff_resolve = set(union_T[t] for t in self.function_diff_results if t in union_T )
        # boundary_diff_resolve = set(union_T[t] for t in self.boundary_diff_results if t in union_T )
        function_diff_resolve = self.function_diff_results
        boundary_diff_resolve = self.boundary_diff_results
        file_diff_resolve     = self.file_diff_results

        if function_diff_resolve != None and len(function_diff_resolve) != 0:
            function_diff_resolve = set(self.solver.find_matching_indices(scope="focus",indices=list(function_diff_resolve))[0].values())
        else:
            function_diff_resolve = set()

        if boundary_diff_resolve != None and len(boundary_diff_resolve) != 0:
            boundary_diff_resolve = set(self.solver.find_matching_indices(scope="focus", indices=list(boundary_diff_resolve))[0].values())
        else:
            boundary_diff_resolve = set()

        if file_diff_resolve != None and len(file_diff_resolve) != 0:
            file_diff_resolve = set(self.solver.find_matching_indices(scope="focus", indices=list(file_diff_resolve))[0].values())
        else:
            file_diff_resolve = set()
        logger.info(f"Function diff results: {len(function_diff_resolve)}")
        logger.info(f"Boundary diff results: {len(boundary_diff_resolve)}")
        logger.info(f"File diff results: {len(file_diff_resolve)}")
        overlap = boundary_diff_resolve & function_diff_resolve & file_diff_resolve
        logger.info("%s", overlap)
        try:
            logger.info(f"Boundary Before: {len(self.project_before.input_boundary)}")
            logger.info(f"Boundary After: {len(self.project_after.input_boundary)}")
        except Exception as e:
            logger.error(f"Boundary error: {e}")

        # logger.info(f"File diff results before LLM check: {len(self.file_diff_result_before_llm)}")

        logger.info(f"Overlap between function, boundary, and file diff results: {len(overlap)}")

        union = function_diff_resolve | boundary_diff_resolve | file_diff_resolve
        logger.info(f"Union of function, boundary, and file diff results: {len(union)}")

        heuristic =  (function_diff_resolve & boundary_diff_resolve) | file_diff_resolve
        logger.info(f"Heuristic of function, boundary, and file diff results: {len(heuristic)}")

        report = {
            "function_diff": list(function_diff_resolve),
            "boundary_diff": list(boundary_diff_resolve),
            "file_diff": list(file_diff_resolve),
            "overlap": list(overlap),
            "union": list(union),
            "heuristic": list(heuristic)
        }
        save_json(self.diffguy_report_path, report)

    def output_sad_empty_report(self):
        report = {
            "function_diff": list(),
            "boundary_diff": list(),
            "file_diff": list(),
            "overlap": list(),
            "union": list(),
            "heuristic": list(),
        }
        save_json(self.diffguy_report_path, report)
