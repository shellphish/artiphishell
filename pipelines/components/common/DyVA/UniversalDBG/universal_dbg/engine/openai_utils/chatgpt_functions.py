import hashlib
import json
import os
import yaml
import string
import requests
import yaml
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Dict
from universal_dbg.engine.openai_utils.functions_api import chatgpt_function, fetch_function_source_using_signature, get_most_similar_function_signature, convert_python_dict_to_text
from universal_dbg.engine.openai_utils.utils import print_colored_messages
from universal_dbg.engine.openai_utils.globals import MODEL, CLIENT
from universal_dbg.engine.gdb_helper import gdb_helper
import re
# import globals

TARGET = None
SRC_ROOT_PATH = None
SRC_FILE_NAME = None
BINARY_PATH = None
INPUT_DATA = None
OUTPUT_PATH = None
GDB_REMOTE = None
IS_ARGV = None
GDB_REMOTE = None
INPUT_FILE_PATH = None
FUNCTIONS_PATH = None
# PROPOSED_ROOT_CAUSE = globals.PROPOSED_ROOT_CAUSE

FUNCTIONS_BY_FULLNAME = dict()
FUNCTIONS_FOR_SIMPLE_FUNCNAME = defaultdict(list)
FUNCTIONS_METADATA = dict()
FUNC_CALLS_FROM_FUNC = defaultdict(set)
FUNC_CALLS_TO_FUNC = defaultdict(set)
FUNCTION_SRC_PATH = None
MESSAGES = []


def append_message(msg):
    global MESSAGES
    print_colored_messages([msg])
    MESSAGES.append(msg)

def set_function_src_path(path):
    global FUNCTION_SRC_PATH
    FUNCTION_SRC_PATH = path

def split_function(name):
    'split the function name by `.` and `:`'
    name, sig = name.split(":") if ":" in name else (name, "")
    name_segs = name.split(".")
    return list(name_segs) + [sig] if sig else name_segs


def similarity(a, b):
    return SequenceMatcher(None, split_function(a), split_function(b)).ratio()

class SimilarFunctionFoundError(Exception):
    def __init__(self, provided, most_similar, similar_functions, *args: object) -> None:
        super().__init__(*args)
        self.provided = provided
        self.most_similar = most_similar
        self.similar_functions = similar_functions

    def __str__(self) -> str:
        return f"""
# FUNCTION LOOKUP ERROR
The function you requested ({self.provided!r}) was not found.
However, a very similar function name ({self.most_similar!r}) was found.
Here are some VALID suggestions for FULL function names which you MUST use. Please retry with ONE of the following:
```yaml
{yaml.dump({"similar_functions": self.similar_functions})}
```
"""

class ShortFunctionNameFoundError(Exception):
    def __init__(self, provided, similar_functions, *args: object) -> None:
        super().__init__(*args)
        self.provided = provided
        self.similar_functions = similar_functions

    def __str__(self) -> str:
        if len(self.similar_functions) > 1:
            return f"""
# FUNCTION LOOKUP ERROR
The function you requested ({self.provided!r}) was found but it is ambiguous. Here are some VALID suggestions. Please retry with ONE of the following:
```yaml
{yaml.dump({"similar_functions": self.similar_functions})}
```
"""
        else:
            return f"""
# FUNCTION LOOKUP ERROR
The function you requested ({self.provided!r}) was found but it is incomplete. You must specify the full function name. Here is a VALID suggestion. Please retry with ONE of the following:
```yaml
{yaml.dump({"similar_functions": self.similar_functions})}
```"""

class NoFunctionFoundError(Exception):
    def __init__(self, provided, similar_functions, *args: object) -> None:
        super().__init__(*args)
        self.provided = provided
        self.similar_functions = similar_functions
    def __str__(self) -> str:
        return f"""

        
# FUNCTION LOOKUP ERROR
The function you requested ({self.provided!r}) cannot be found. Are you sure that is a function? If you are sure, it's probably a library function. If you are sure it's a function, please specify the full function name.
Here's the closest VALID function names we've found. Please retry with ONE of the following if you are sure it's a function:
```yaml
{yaml.dump({"similar_functions": self.similar_functions})}
```
"""

def verify_function_name(name):
    if name in FUNCTIONS_BY_FULLNAME:
        return

    # find most similar function name
    closest_functions = list(sorted(FUNCTIONS_BY_FULLNAME.keys(), key=lambda k: similarity(name, k), reverse=True))[:5]
    if len(closest_functions):
        most_similar = closest_functions[0]
        if similarity(name, most_similar) > 0.8:
            raise SimilarFunctionFoundError(name, most_similar, closest_functions)

    if name in FUNCTIONS_FOR_SIMPLE_FUNCNAME and FUNCTIONS_FOR_SIMPLE_FUNCNAME[name]:
        raise ShortFunctionNameFoundError(name, FUNCTIONS_FOR_SIMPLE_FUNCNAME[name])
    else:
        # find the most similar function name
        most_similar_short = max(FUNCTIONS_FOR_SIMPLE_FUNCNAME.keys(), key=lambda k: similarity(name, k))
        if similarity(name, most_similar_short) > 0.8:
            raise SimilarFunctionFoundError(name, most_similar_short, FUNCTIONS_FOR_SIMPLE_FUNCNAME[most_similar_short])
        else:
            raise NoFunctionFoundError(name, closest_functions)


# setting globals
def set_globals(src_root_path, binary_path, output_path, is_argv, gdb_remote):
    global SRC_ROOT_PATH, BINARY_PATH, OUTPUT_PATH
    SRC_ROOT_PATH = src_root_path
    BINARY_PATH = binary_path
    OUTPUT_PATH = output_path
    if is_argv:
        global IS_ARGV
        IS_ARGV = True
    if gdb_remote:
        global GDB_REMOTE
        GDB_REMOTE = gdb_remote

def set_input_data(input_file_path):
    global INPUT_DATA, INPUT_FILE_PATH
    INPUT_FILE_PATH = input_file_path
    with open(input_file_path, "rb") as f:
        input_data = f.read()
    INPUT_DATA = input_data

# This is the old function, gives too much info
# def obtain_directory_structure_as_str(dir_path):
#     """
#     This function returns the directory structure as a string
#     something like:
#         dir_path
#         ├── file1
#         ├── file2
#         └── subdir1/
#             ├── file1
#             └── file2
#     """
#     directory_structure = ""
#     for dirpath, dirnames, filenames in os.walk(dir_path):
#         directory_structure += f"{dirpath}\n"
#         for file in filenames:
#             directory_structure += f"├── {file}\n"
#         for dirname in dirnames:
#             directory_structure += f"└── {dirname}\n"
#     return directory_structure


def obtain_directory_structure_as_str(dir_path):
    """
    This function returns the directory structure as a string
    something like:
        dir_path
        ├── file1
        ├── file2
        └── subdir1/
    """
    directory_structure = ""
    all_files = os.listdir(dir_path)
    for file in all_files:
        directory_structure += f"├── {file}\n"
    return directory_structure
# def convert_python_dictionary_to_string(dictionary):
#     """
#     This function converts a python dictionary to a string, it should also handle nested dictionary structure (using recursive calls), with proper indentation.
#     """
#     string = ""
#     for key, value in dictionary.items():
#         if isinstance(value, dict):
#             string += f"{key}:\n"
#             string += convert_python_dictionary_to_string(value)
#         else:
#             string += f"{key}: {value}\n"
#     return string

# def get_gdb_crash_report():
#     ## this part is copied from claude output
#     import re
#     # Read the file content
#     with open(GDB_CRASH_REPORT_PATH, 'r') as my_file:
#         data = my_file.read()

#     # Remove all '─' characters
#     data = data.replace('─', '')

#     # Replace multiple spaces with a single space, but keep newlines
#     data = re.sub(r'[^\S\n]+', ' ', data)

#     # Remove leading and trailing whitespace from each line
#     data = '\n'.join(line.strip() for line in data.splitlines())

#     return data

def get_crash_context():
    """
    :param input: The input that caused the crash.
    :return: A dictionary containing information about the crash context.
    """
    
    crash_context = gdb_helper.crash_and_get_context(input_data=INPUT_FILE_PATH if IS_ARGV else INPUT_DATA, binary_path=BINARY_PATH, remote=GDB_REMOTE, is_file=IS_ARGV)
    return crash_context

def get_input_data():
    return INPUT_DATA

# def load_functions():
#     # first fetch all functions
#     for dirpath, dirnames, filenames in os.walk(FUNCTIONS_PATH):
#         for filename in filenames:
#             if filename.endswith(".json"):
#                 full_path = os.path.join(dirpath, filename)
#                 with open(full_path, "r") as f:
#                     j = json.load(f)
#                 # escape code
#                 # j["code"] = j["code"].replace("\n", "\\n").replace("\t", "\\t")
#                 FUNCTIONS_BY_FULLNAME[j["full_funcname"]] = j["code"]
#                 FUNCTIONS_FOR_SIMPLE_FUNCNAME[j["funcname"]].append(j["full_funcname"])
#                 FUNCTIONS_METADATA[j["full_funcname"]] = {
#                     "filename": j["filename"],
#                     "funcname": j["funcname"],
#                     "full_funcname": j["full_funcname"],
#                     "lines": j["lines"],
#                 }
#     # then fetch all function calls (and filter out unknown functions)
#     for dirpath, dirnames, filenames in os.walk(FUNCTIONS_PATH):
#         for filename in filenames:
#             if filename.endswith(".json"):
#                 full_path = os.path.join(dirpath, filename)
#                 with open(full_path, "r") as f:
#                     j = json.load(f)

#                 if not "func_calls_in_func" in j:
#                     continue

#                 for func in j["func_calls_in_func"]:
#                     if func not in FUNCTIONS_BY_FULLNAME:
#                         # skip unknown functions
#                         continue
#                     FUNC_CALLS_FROM_FUNC[j["full_funcname"]].add(func)
#                     FUNC_CALLS_TO_FUNC[func].add(j["full_funcname"])
# @chatgpt_function
# def get_contextual_function_summary(name: str, query: str, **kwargs):
#     """
#     Returns a shortened summary of the source code of the function named `name`.
#     The summary is generated to assist the user in solving the problem described in `query`.
#     This has no context from any previous conversation, so the query should be very specific to the problem at hand and include all necessary information to be helpful.
#     E.g. if the user is trying to exploit a buffer overflow, the query should be something like
#     "How can I exploit the buffer overflow in the function `name` which arises from the use of the 'gets' function?".

#     If the response is not specific enough, you can try again with a more specific query or add more context information to the query.

#     :param name: The name of the function to summarize.
#     :param query: The query that the user would like to answer using the summary.
#     :return: The summary of the function named `name` in the context of the query `query`.
#     """
#     verify_function_name(name)
#     source = FUNCTIONS_BY_FULLNAME.get(name, None)
#     if source is None:
#         return None

#     # generate a contextual summary using the gpt-3.5-turbo model

#     N_TOKENS = 500
#     model = kwargs.pop('model', MODEL)
#     print(f"Using model {model}")
#     result = CLIENT.chat.completions.create(
#         model=kwargs.pop('model', MODEL),
#         messages=[
#             dict(role='user', content=f"Q: What is the function {name}?"),
#             dict(role='assistant', content=f"A: {source}",),
#             dict(role='user', content=f"Q: Can you summarize it and help the user answer the query {query!r}? Be succint and include only relevant information. Walk the user through the reasoning in steps. You have {N_TOKENS} tokens. Include a skeleton of the function code containing only the pieces of code that are relevant to the query."),
#         ],
#         temperature=kwargs.pop('temperature', 0.0),
#         max_tokens=kwargs.pop('max_tokens', N_TOKENS),
#         stop=["Q:"],
#         **kwargs
#     )
#     # import ipdb; ipdb.set_trace()
#     summary = result["choices"][0]['message']["content"]
#     if summary.startswith("A:"):
#         summary = summary[2:]
#     summary = summary.strip()
#     return summary

@chatgpt_function
def get_lines_from_src(src_file_name, start_line, end_line):
    """
    :param src_file_name: The name of the source file to extract the source code from.
    :param start_line: The starting line number within the src_file_path to extract.
    :param end_line: The ending line number within the send_line to extract.
    :return: The source code between the specified start and end lines in the src_file_path.

    Note: Do not pass the datatype of function, for example if you want to call void main(), just pass main() as the function_identifier.
    Note: Global variables cannot be accessed in this function.
    """

    src_file_path = os.path.join(SRC_ROOT_PATH, src_file_name)
    source = gdb_helper.get_line_src(src_file_path, start_line, end_line)
    return source


# @chatgpt_function
# def get_function_source(src_file_name: str, function_identifier: str):
#     """
#     This function retrieves the source code for the specified function from the source file.
#     :param src_file_name: The name of the source file to extract the source code from.
#     :param function_identifier: The identifier of the function to return the source code for (function name). This should be as specific as possible, e.g. usually it includes the signature if present.
#     :return: The source code for the function named `name` and line numbers where the function is defined.

#     Note: Do not pass the datatype of function, for example if you want to call void main(), just pass main() as the function_identifier.
#     Note: Global variables cannot be accessed in this function.
#     """

#     src_file_path = os.path.join(SRC_ROOT_PATH, src_file_name)
#     source = gdb_helper.get_function_src(src_file_path, function_identifier)
#     return source

@chatgpt_function
def get_function_source(function_signature: str):
    """
    This function retrieves the source code for the specified function from the source file.
    param function_signature: str, the signature of the function to retrieve the source code for.
    return str, the source code for the function or list of most similar signatures.
    """
    function_dict = fetch_function_source_using_signature(function_signature)
    if "error" in function_dict:
        function_dict = get_most_similar_function_signature(function_signature)
    return convert_python_dict_to_text(function_dict)


@chatgpt_function
def get_context_and_registers_between_lines(start_line: str, end_line: str, src_file_name: str):

    """
    Retrieves context, local variables, and register information for each instruction between the specified start and end lines in the source code.

    :param start_line: The starting line number within the src code to analyze.
    :param end_line: The ending line number within the src code to analyze.
    :param src_file_name: The name of the source file to analyze.
    
    :return: A dictionary containing context information for each instruction between the specified start and end lines.

    Note:
    - INPUT_DATA: Global variable automatically passed, consisting of input data for the program.
    - SRC_ROOT_PATH: Global variable automatically passed, consisting of the path to the root dir.
    - BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.
    """
    SRC_FILE_PATH = os.path.join(SRC_ROOT_PATH, src_file_name)
    trace = gdb_helper.get_context_and_registers_between_addresses_helper(start_line, end_line, INPUT_DATA, BINARY_PATH, SRC_FILE_PATH, remote=GDB_REMOTE, is_argv=IS_ARGV)
    return trace


@chatgpt_function
def get_context_and_registers_for_function(function_identifier: str, src_file_name: str):
    """
    This function retrieves a dictionary containing information about the backtrace, local variables, and registers for each instruction in the specified function using by performing dynamic execution using GDB.

    :param function_identifier: The identifier of the function to analyze using gdb. This should include the function signature, e.g., "functionName(arg1, arg2, ...)" or "functionName()" if no arguments are known.
    :param src_file_name: The name of the source file to analyze.

    :return: A dictionary containing context information for each instruction in the function.

    Note:
    - INPUT_DATA: Global variable automatically passed, consisting of input data for the program.
    - SRC_ROOT_PATH: Global variable automatically passed, consisting of the path to the root dir.
    - BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.
    """
    print("Retrieving context and registers for the entire function")
    
    SRC_FILE_PATH = os.path.join(SRC_ROOT_PATH, src_file_name)
    trace = gdb_helper.get_context_and_registers_for_function_helper(function_identifier, INPUT_DATA, BINARY_PATH, SRC_FILE_PATH, remote=GDB_REMOTE, is_argv=IS_ARGV)
    return trace


@chatgpt_function
def propose_root_cause(yaml_report: str):
    """
    param yaml_report: str, yaml report 
    The structure of the yaml_report is as follows: 
    {   "function_name": "The name of the function that was the root cause of the crash",
        "root_cause": "The root cause of the crash, explain the bug in detail",
        "root_cause_diff_from_crash_site": "Yes/No", 
        "solution": "specific solution to the bug"
        "security_vulnerability": "Yes/No"
        "proposed_patch": "The proposed patch to fix the bug, only provide the code snippet that needs to be changed"
    }
    """
    # we write to OUTPUT_PATH
    # write the yaml_report to OUTPUT_PATH
    try:
        print("yaml_report: {}".format(yaml_report))
        with open(os.path.join(OUTPUT_PATH), "w") as f:
            f.write(yaml_report)
    except Exception as e:
        print("Error writing to output path: {}".format(e))
        return "Error writing to output path"

    return "Root cause and solution proposed successfully written to the output path, now call finish_task function"


    


@chatgpt_function
def set_break_point_and_get_context(src_file_name: str, line_number: int):
    """
    Sets a breakpoint at the specified line number in the source code and retrieves the context and registers at that breakpoint.
    :param src_file_name: The name of the source file to analyze. Note: The source file should be in the root_path directory.
    :param line_number: The line number in the source code where the breakpoint should be set.
    :return: A dictionary containing context information at the breakpoint.
    
    Note:
    - INPUT_DATA: Global variable automatically passed, consisting of input data for the program.
    - SRC_FILE_PATH: Global variable automatically passed, consisting of the path to the source file.
    - BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.
    """
    SRC_FILE_PATH = os.path.join(SRC_ROOT_PATH, SRC_FILE_NAME)
    trace = gdb_helper.set_break_point_and_get_context_helper(line_number, INPUT_DATA, BINARY_PATH, SRC_FILE_PATH, remote=GDB_REMOTE, is_argv=IS_ARGV)
    return trace
