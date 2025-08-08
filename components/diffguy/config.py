"""
Configuration settings for the CodeQL analyzer.
"""
import os
from typing import Dict, Any

# CodeQL server URL from environment variable with default
CODEQL_SERVER_URL = os.environ.get("CODEQL_SERVER_URL", "http://172.17.0.4:4000")

# How many processes are we using in parallel
NUM_PROCESSES = 15

DIFFGUY_TIMEOUT = 60 * 60  # 1 hour in seconds

DIFFGUY_MODELS = ['claude-4-sonnet', 'o3']

NAP_DURATION = 5 # minutes
NAP_SNORING = 60  # seconds
NAP_BECOMES_FAIL_AFTER: int = 10

# Path configurations
QUERY_PATHS = {
    "vuln_query": "vuln_query",
    "boundary_query": "boundary_query",
    "input_boundary": os.path.join("boundary_query", "input_boundary_new.ql"),
    # "sink_boundary": os.path.join("boundary_query", "sink_boundary_new.ql")   #not in use
}

# File name templates
FILE_TEMPLATES = {
    "vulns_result": "function_{project_name}.json",
    "boundary_result": "boundary_{project_name}.json",
    "func_diff_result": "diff_func_{project_name}.json",
    "boundary_diff_result": "diff_boundary_{project_name}.json",
    "file_diff_result": "diff_file_{project_name}.json",
    "query_result": "query_{query_name}_{project_name}.json",
    "diffguy_report" : "diffguy_report.json",
    # "sink_boundary_result": "boundary_{function_name}_sink_{project_name}.json"   # not in use
}
PROMPT_PATHS = {
    "system_prompt" : "/shellphish/diffguy/prompt/system.j2",
    "user_prompt" : "/shellphish/diffguy/prompt/user.j2",
}
# Analysis modes
DIFF_MODES = ["function", "boundary", "file", "all"]
LANGUAGES = ["c","c++", "jvm"]
RUN_MODES = ["remote", "local"]


SANITIZER_TO_FIELD = {
    'alloc_then_loop': 'derefExpr',
    'stack_const_alloc': 'access',
    'stack_buf_loop': 'access',
    'alloc_const': 'allocPosition',
}

# Maximum length functions for file diff
MAX_FUNCTIONS_IN_FILE_DIFF = 1500
