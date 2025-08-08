"""
Utility functions for the CodeQL analyzer.
"""
import os
import json
import logging
from typing import Any, Dict, List, Optional
import re
from collections import defaultdict
import whatthepatch


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logging.getLogger('httpx').setLevel(logging.WARNING)

SANITIZER_TO_FIELD = {
    'alloc_then_loop': 'derefExpr',
    'stack_const_alloc': 'access',
    'stack_buf_loop': 'access',
    'alloc_const': 'allocPosition',
}

def save_json(path: str, data: Any) -> None:
    """Save data to a JSON file.

    Args:
        path: File path to save the data
        data: Data to save
    """
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        logger.debug(f"Data saved to {path}")
    except Exception as e:
        logger.error(f"Error saving data to {path}: {e}")
        raise

def load_json(path: str) -> Any:
    """Load data from a JSON file.

    Args:
        path: File path to load the data from

    Returns:
        Loaded data
    """
    try:
        with open(path, "r") as f:
            data = json.load(f)
        logger.debug(f"Data loaded from {path}")
        return data
    except Exception as e:
        logger.error(f"Error loading data from {path}: {e}")
        raise

def extract_file_id(vulnerability_id: str):
    """
    Use regex to extract the file identifier from a vulnerability ID.
    return tuple of (file_path, row_start)
    """
    # Regex patterns with proper Python named group syntax
    PATTERN_EXTRACT_ALL = r"^(?:file://)?(?P<filepath>.+?):(?P<row_start>\d+):\d+:\d+:\d+$"
    match = re.match(PATTERN_EXTRACT_ALL, vulnerability_id)
    try:
        file_path = match.group('filepath')
        row_start = int(match.group('row_start')) if match.group('row_start') else None
        return file_path, row_start
    except Exception as e:
        raise ValueError(
            f"Failed to extract file identifier from vulnerability ID '{vulnerability_id}': {e}"
        ) from e


def extract_info_from_query_result(sanitizer, query_result: Dict[str, Any]) -> tuple:
    """
    Extract file path, function name and vuln location from a query result.

    Args:
        query_result: A single query result dictionary
    Returns:
        tuple: (file_path, func_name, vuln_location)
    """
    # Extract file identifier from the vulnerability ID
    file_path, row_start = extract_file_id(query_result['id'])

    func_name = query_result.get('name', '')
    vuln_location = None

    if SANITIZER_TO_FIELD.get(sanitizer):
        # Extract the vuln location from the sanitizer field
        _, vuln_location = extract_file_id(query_result[SANITIZER_TO_FIELD[sanitizer]])

    return file_path, func_name, row_start, vuln_location

def group_vulnerabilities_by_function(data):
    """Group vulnerability data by function.
    Args:
        data: Vulnerability data
    Returns:
        Data grouped by function
    """
    # Key: file_path:func_name
    if not data:
        return {}
    grouped_data = {}


    for sanitizer, query_results in data.items():

        for query_result in query_results:
            file_path, func_name, row_start, vuln_location = extract_info_from_query_result(sanitizer, query_result)
            unique_key = f"{file_path}:{func_name}"
            if unique_key not in grouped_data:
                # Initialize the entry if it doesn't exist
                grouped_data[unique_key] = {
                    "row_start": row_start,
                    "file_path": file_path,
                    "func_name": func_name,
                    # Vuln locations: key -- sanitizer name, value -- list of vuln locations
                    "sanitizer_to_vuln_locations": {san: [] for san in data.keys()}
                }
            # Add the vuln location if it exists
            # Will add None if the sanitizer didn't provide a location
            grouped_data[unique_key]["sanitizer_to_vuln_locations"][sanitizer].append(vuln_location)
    return grouped_data


def ensure_directories(*paths: str) -> None:
    """Ensure that directories exist.

    Args:
        *paths: Directory paths to create
    """
    for path in paths:
        os.makedirs(path, exist_ok=True)
        logger.debug(f"Directory ensured: {path}")
'''
    {
        "entryPoint": "LLVMFuzzerTestOneInput",
        "entryPointId": "file:///src/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc:100:16:100:37",
        "end": "OSS_FUZZ_png_image_free",
        "endId": "file:///src/libpng/png.c:4632:1:4632:14"
    },
'''

def reformat_boundary(boundary_data):
    grouped_data = {}
    for item in boundary_data:
        entry_name = item["entryPoint"]
        entryId = item["entryPointId"]
        end_name = item["end"]
        endId = item["endId"]
        PATTERN_EXTRACT_ALL = r"^(?:file://)?(?P<filepath>.+?):(?P<row_start>\d+):\d+:\d+:\d+$"
        entry_match = re.match(PATTERN_EXTRACT_ALL, entryId)
        end_match = re.match(PATTERN_EXTRACT_ALL, endId)

        try:
            entry_file_path = entry_match.group('filepath')
            end_file_path = end_match.group('filepath')
            end_row_start = end_match.group('row_start')
            id = f"{end_file_path}:{end_name}"
            grouped_data[id] = {
                "row_start": end_row_start,
                "file_path": end_file_path,
                "func_name": end_name,
                "entryPoint": {
                    "harness_func_name" : entry_name,
                    "harness_file_path": entry_file_path
                }
            }
        except Exception as e:
            logger.error(f"Error extracting file identifier from entryId '{entryId}': {e}")
            continue
    return grouped_data



def function_resolve(data, language, solver):
    union_T = {}
    for t in data:
        arr = t.split(":")
        if len(arr) == 3:
            filename,function0,lineno = arr
        else:
            filename = arr[0]
            function0 = ":".join(arr[1:-1])
            lineno = arr[-1]
        try:
            if language == "c" or language == "c++":
                lineno_1 = str(int(lineno) -1)
                function = function0

                ids_by_func = solver.find_by_funcname(function)
            if language == "jvm":
                lineno_1 = lineno
                function = function0.split(".")[-1]
                ids_by_func = solver.find_by_funcname(function)
        except Exception as e:
            ids_by_func = []
            logger.warning(f"Can not resolve function {function0}")
        try:
            ids_by_file = solver.find_by_filename(filename)
        except Exception as e:
            logger.warning(f"Can not resolve file {filename}: {e}")
            ids_by_file = []

        N = list(set(ids_by_func) & set(ids_by_file))
        id = f"{filename}:{function0}:{lineno}"
        if N == []:
            pass
        elif len(N) == 1:
            union_T[id] = N[0]
        else:
            for key in N:
                if key.split(":")[1] == lineno_1:
                    union_T[id] = key
                    break
            union_T[id] = N[0]

    return union_T

def get_diff(func_resolver, function_index: str, diff_text: str , bot=True):
    # path = str(func_resolver.get_focus_repo_relative_path(function_index))
    path = str(func_resolver.get(function_index).target_container_path)
    name = func_resolver.get_funcname(function_index)
    boundary = func_resolver.get_function_boundary(function_index)
    ALL_TEXT = ""
    flag = 0
    for diff in whatthepatch.parse_patch(diff_text):
        if  diff.header.new_path not in path:
            continue
        match = re.split(r"(@@ -\d+,\d+ \+\d+,\d+ @@)", diff.text)
        results_tmp = {}
        text = match[0]
        for snippet in match[1:]:
            if snippet.startswith("@@"):
                match_header = re.match(r"@@ -(\d+),\d+ \+(\d+),(\d+) @@", snippet)
                base_line = int(match_header.group(1))
                target_line = int(match_header.group(2))
                changed_lines = int(match_header.group(3))
                if  boundary[0]>target_line+changed_lines or boundary[1]<target_line:
                    should_include = False
                else:
                    should_include = True
                    text += (snippet+match[match.index(snippet) + 1])+ "\n"
                    flag = 1
                    # print("Found diff for function %s in file %s" % (name, path))

                results_tmp[snippet] = {
                    "target_line": target_line,
                    "base_line": base_line,
                    "snippet": snippet + match[match.index(snippet) + 1],
                    "include": should_include
                }
        ALL_TEXT += text

    if flag == 0:
        logger.info("Can't find diff for function %s in file %s" % (name, path))
        if bot == True:
            return f"THE CODE OF  `{name}` WAS NOT CHANGED IN THE DIFF FILE"
        else:
            return f"THE CODE OF  `{name}` WAS NOT CHANGED IN THE DIFF FILE"
    else:
        # logger.info("Found diff for function %s in file %s" % (name, path))
        if bot == True:
            return ALL_TEXT
        else:
            return ALL_TEXT