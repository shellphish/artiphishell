import os
import logging
from typing import Dict, List, Tuple, Any, Optional, Set
import sys
import yaml
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.project import Project
from config import FILE_TEMPLATES, QUERY_PATHS
from core.utils import save_json, load_json, ensure_directories, function_resolve
from shellphish_crs_utils.function_resolver import FunctionResolver


logger = logging.getLogger(__name__)

class BoundaryDiffAnalyzer:
    """Class to analyze function-level differences between two versions of a project."""

    def __init__(self, project: str, project_before: Project, project_after: Project, language:str, query_path: str, save_path: str, solver: FunctionResolver):
        self.name = project
        self.project_before = project_before
        self.project_after = project_after
        self.language = language
        self.query_dir = os.path.join(query_path, QUERY_PATHS["vuln_query"])
        self.save_path = save_path
        ensure_directories(self.save_path)
        self.boundary_diff_path = os.path.join(self.save_path, FILE_TEMPLATES["boundary_diff_result"].format(project_name=self.name))
        self.boundary_diff_results = None
        self.boundary_diff_result_list = None
        self.solver = solver
        self.load_boundary_diff_results()



    def load_boundary_diff_results(self):
        if os.path.exists(self.boundary_diff_path):
            logger.debug(f"Boundary diff results already exist, loading from file")
            self.boundary_diff_results = load_json(self.boundary_diff_path)
        else:
            self.reformat_result_before = self.project_before.input_boundary
            self.reformat_result_after = self.project_after.input_boundary
            self.boundary_diff_results = self.analyze_boundary_differences()

        if self.boundary_diff_results == None:
            logger.error(f"Boundary DIFF ERROR")
            self.boundary_diff_result_list = set()
        else:
            diff_boundary_set = set(f"{file_path}:{func_name}:{row_start}" for file_path, func_name, row_start in [(v["file_path"], v["func_name"], v["row_start"]) for k, v in self.boundary_diff_results.items()])
            # self.boundary_diff_result_list = self.boundary_diff_results.keys()

            resolved_functions = function_resolve(list(diff_boundary_set), self.language, self.solver)
            boundary_diff_resolve = set(resolved_functions[t] for t in diff_boundary_set if t in resolved_functions)
            self.boundary_diff_result_list = boundary_diff_resolve

    def analyze_boundary_differences(self):
        logger.info(f"Analyzing boundary differences for project {self.name}")
        if self.reformat_result_after == None or self.reformat_result_before == None:
            save_json(self.boundary_diff_path, None)
            return None

        diff_boundary_dict = {}

        for id in self.reformat_result_after.keys():
            if id not in self.reformat_result_before:
                if id not in diff_boundary_dict:
                    diff_boundary_dict[id] = {
                        "func_name": self.reformat_result_after[id]["func_name"],
                        "file_path": self.reformat_result_after[id]["file_path"],
                        "row_start": self.reformat_result_after[id]["row_start"] if self.reformat_result_after[id]["row_start"] else None,
                    }

        save_json(self.boundary_diff_path, diff_boundary_dict)
        return diff_boundary_dict






