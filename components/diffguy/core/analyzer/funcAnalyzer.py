import os
import logging
from typing import Dict, List, Tuple, Any, Optional, Set
import sys
import yaml
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.project import Project
from config import FILE_TEMPLATES, QUERY_PATHS, SANITIZER_TO_FIELD
from core.utils import save_json, load_json, ensure_directories, function_resolve
from shellphish_crs_utils.function_resolver import FunctionResolver

logger = logging.getLogger(__name__)

class FunctionDiffAnalyzer:
    """Class to analyze function-level differences between two versions of a project."""

    def __init__(self, project_name: str, project_before: Project, project_after: Project, language:str, query_path: str, save_path: str, solver: FunctionResolver):
        self.name = project_name
        self.project_before = project_before
        self.project_after = project_after
        self.language = language
        self.query_dir = os.path.join(query_path, QUERY_PATHS["vuln_query"])
        self.save_path = save_path
        ensure_directories(self.save_path)
        self.func_diff_path = os.path.join(self.save_path, FILE_TEMPLATES["func_diff_result"].format(project_name=self.name))
        self.func_diff_results = None
        self.func_diff_result_list = None
        self.grouped_result_before = None
        self.grouped_result_after = None
        self.solver = solver
        self.sanitizer = self.get_sanitizer_list()
        self.load_function_diff_results()


    def load_function_diff_results(self):
        if os.path.exists(self.func_diff_path):
            logger.debug(f"Function diff results already exist, loading from file")
            self.func_diff_results = load_json(self.func_diff_path)
        else:
            self.grouped_result_before = self.project_before.vulns_result
            self.grouped_result_after = self.project_after.vulns_result
            self.func_diff_results = self.analyze_function_differences()

        diff_functions_set = set(f"{file_path}:{func_name}:{row_start}" for file_path, func_name, row_start in [(v["file_path"], v["func_name"], v["row_start"]) for k, v in self.func_diff_results.items()])
        # self.func_diff_result_list = diff_functions_set
        resolved_functions = function_resolve(list(diff_functions_set), self.language, self.solver)
        function_diff_resolve = set(resolved_functions[t] for t in diff_functions_set if t in resolved_functions)
        logger.info(f"Functions diff(may not reachable): {len(function_diff_resolve)} functions")
        try:
            if self.language != "jvm":
                boundary_after = set( f"{item[0]}:{item[1]['row_start']}" for item in self.project_after.input_boundary.items())
                solved_funcs = function_resolve(boundary_after, self.language, self.solver)
                boundary_after_resolved = set(solved_funcs[k] for k in solved_funcs)
                logger.info(f"Boundary After Resolved: {len(boundary_after_resolved)} functions")
                func_diff_result_list = boundary_after_resolved & function_diff_resolve
                self.func_diff_result_list = func_diff_result_list
            else:
                self.func_diff_result_list = function_diff_resolve
        except Exception as e:
            logger.error(f"self.project_after.input_boundary error: {e}")
            self.func_diff_result_list = function_diff_resolve

    def analyze_function_differences(self):
        """Compare function statistics between before and after versions.

        Identifies changed, new, and deleted functions.

        Returns:
            Dictionary of function differences by sanitizer and file
        """
        logger.info(f"Analyzing function differences for project {self.name}")

        diff_function_dict = {}
        if not self.grouped_result_before or not self.grouped_result_after:
            logger.warning("Grouped results not available for function comparison. Please run vulnerability analysis first.")
            return diff_function_dict

        # Compare the grouped results
        for unique_key in self.grouped_result_after.keys():
            if unique_key not in self.grouped_result_before:
                vul_function_obj = self.grouped_result_after[unique_key]
                # Add to diff set as a new function
                file_path = vul_function_obj["file_path"]
                func_name = vul_function_obj["func_name"]
                row_start = vul_function_obj["row_start"]
                sanitizer_to_vuln_locations = {}

                # process the sanitizer exceptions
                for k, v in vul_function_obj["sanitizer_to_vuln_locations"].items():
                    if ((v) and (k in self.sanitizer)):
                        sanitizer_to_vuln_locations[k] = {
                            'count_before': 0,
                            'count_after': len(v),
                            'vul_locs_before': [],
                            'vul_locs_after': v
                        }
                if sanitizer_to_vuln_locations == {}:
                    continue

                # Mark as new in the diff dictionary
                if unique_key not in diff_function_dict:
                    diff_function_dict[unique_key] = {
                        "file_path": file_path,
                        "func_name": func_name,
                        "row_start": row_start,
                        # Include only the sanitizer to vuln locations that are non-empty
                        "sanitizer_to_vuln_locations": sanitizer_to_vuln_locations
                    }
            else:
                # Function exists in both before and after, check for differences
                vul_function_before = self.grouped_result_before[unique_key]
                vul_function_after = self.grouped_result_after[unique_key]

                # Only keep vuln locations that are different between before and after
                #
                filtered_sanitizer_to_vuln_locations = {}
                # Iterate over each sanitizer to compare vulnerability locations
                # import ipdb; ipdb.set_trace()
                for sanitizer in self.sanitizer:
                    # Compare the length of vulnerability locations for the sanitizer (as a count of vulnerabilities)
                    vuln_locations_count_before = len(vul_function_before["sanitizer_to_vuln_locations"][sanitizer])
                    vuln_locations_count_after = len(vul_function_after["sanitizer_to_vuln_locations"][sanitizer])
                    if vuln_locations_count_before != vuln_locations_count_after and (vuln_locations_count_before > 0 or vuln_locations_count_after > 0):
                        # If counts are different, add to the filtered dictionary
                        # TODO: REMOVE OVERLAP VULN LOCATIONS APPEAR IN BOTH BEFORE AND AFTER
                        filtered_sanitizer_to_vuln_locations[sanitizer] = {
                            'count_before': vuln_locations_count_before,
                            'count_after': vuln_locations_count_after,
                            'vul_locs_before': vul_function_before["sanitizer_to_vuln_locations"][sanitizer],
                            'vul_locs_after': vul_function_after["sanitizer_to_vuln_locations"][sanitizer]
                        }

                if filtered_sanitizer_to_vuln_locations:
                    # If there are any differences in vulnerability locations, add to the diff set
                    file_path = vul_function_after["file_path"]
                    func_name = vul_function_after["func_name"]
                    row_start = vul_function_after["row_start"]
                    # Update the diff dictionary with the new function object
                    if unique_key not in diff_function_dict:
                        diff_function_dict[unique_key] = {
                            "file_path": file_path,
                            "func_name": func_name,
                            "row_start": row_start,
                            "sanitizer_to_vuln_locations": filtered_sanitizer_to_vuln_locations
                            }

        save_json(self.func_diff_path, diff_function_dict)
        return diff_function_dict


    def get_sanitizer_list(self) -> List[str]:
        sanitizers_before = set(self.project_before.sanitizers)
        sanitizers_after = set(self.project_after.sanitizers)
        sanitizers = sanitizers_before & sanitizers_after
        return sanitizers