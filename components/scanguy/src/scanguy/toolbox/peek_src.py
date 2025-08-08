import os
import json
import logging
import hashlib
import shlex
import subprocess
import re

from agentlib.lib import tools
from pathlib import Path
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES
from shellphish_crs_utils.utils import safe_decode_string
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver
from analysis_graph.models.cfg import CFGFunction
from shellphish_crs_utils.models.coverage import FileCoverageMap, FunctionCoverageMap
from shellphish_crs_utils.models.symbols import SourceLocation

from .peek_utils import tool_error, tool_success, tool_choice

from ..utils import do_grep
from ..config import Config


log = logging.getLogger("scanguy.peek_src")

PeekSrcSkillGlobal = None

#########################
##### 🔨 LLM Tools ######
#########################

@tools.tool
def get_functions_by_file(file_path):
    """
    Open a file and return all of its functions.
    The return type is a list of strings, where each string is a function name.

    :param file_path: The path of the file to open.
    :return: A list of all the function names
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.get_functions_by_file(file_path)


@tools.tool
def show_file_at(file_path: str, offset: int, num_lines_to_show: int) -> str:
    """
    Open a file and return its content.
    A total of num_lines_to_show lines will be shown starting from offset.
    There is a maximum of 100 lines that can be shown at once.
    You can display other lines in the file by changing the offset.

    :param file_path: The path of the file to open.
    :param offset: The line number to start reading from.
    :return: num_lines_to_show lines of the file starting from the specified offset.
             More specifically, the output will be in the format:
             ```
             [File: <file_path> (<total_lines> lines total)]
             (<offset> lines above)
             <line_number>: <line_content>
             ...
             (<lines_below> lines below)
             ```
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.show_file_at(file_path, offset, num_lines_to_show)


@tools.tool
def search_function(func_name: str) -> str:
    """
    Search for a function by its name.
    This tool can be used to retrieve the location of a function definition in the project.

    :param func_name: The name of the function to search for.
    :return: A list of matches with file name and line numbers or an error message if the func_name is not found.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.search_function(func_name)

@tools.tool
def get_function_definition(func_name: str) -> str:
    """
    Get the definition of a function by its name.
    This tool can be used to retrieve the content of a function in the project.

    :param func_name: The name of the function to search for.
    :return: All matched function definitions (concatenated) or an error message if the func_name is not found.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.get_function_definition(func_name)




@tools.tool
def lookup_symbol(expression: str) -> str:
    """
    Search the target source files for a specific expression using grep. The expression should be related to the conditions/functions that can help to reach the sink function.

    Constructs and runs `grep -rnE <expression>` (or `-rniE`/`-rhiE` when context is zero/non-zero)
    in the project directory and returns all matching lines. Use this to find function definitions,
    variable usages, conditional statements, etc.

    Because grep interprets special characters, you must escape any regex metacharacters
    (e.g., backslashes, quotes, brackets) in `expression` so they’re passed correctly to the shell.

    Example:
        To locate all uses of "obj->param", search for "->param" instead of "obj->param".
        This will match every occurrence of "->param" regardless of the object prefix.

    :param expression: A POSIX ERE (extended regex) pattern. Escape any special characters
                       so that the shell does not alter them.
    :return: The raw stdout from the grep command.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.lookup_symbol(expression)

class PeekSrcSkill:
    def __init__(self, **kwargs):

        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        self.function_resolver = kwargs["function_resolver"]
        self.function_indices_path = kwargs["function_index"]
        self.analysis_graph_api = kwargs["analysis_graph_api"]

        self.record = []

        with open(self.function_indices_path, "r") as f:
            self.function_indices = json.load(f)

        # Try to init 3rd party tools and set the config to false if they are not available
        if Config.use_codeql_server:
            from . import CodeQlSkill
            self.codeql = CodeQlSkill(**kwargs)
            Config.use_codeql_server = self.codeql.initialized

        # This is the amount of tool calls we are keeping as "just done"
        # Basically if the LLM issues a tool call that was done in the last X calls, we tell
        # it to try something else.
        self.DUPLICATE_TOOL_CALLS_GUARD_SIZE = 3
        self.last_tool_calls_performed = []

        global PeekSrcSkillGlobal
        PeekSrcSkillGlobal = self

    def __add_to_tool_call_history(self, tool_call_id: str):
        """
        Add a tool call to the history.
        This is used to avoid repeating the same tool call in a short period of time.
        """
        if len(self.last_tool_calls_performed) > self.DUPLICATE_TOOL_CALLS_GUARD_SIZE:
            self.last_tool_calls_performed = self.last_tool_calls_performed[1:]
        self.last_tool_calls_performed.append(tool_call_id)

    def clean_tool_call_history(self):
        self.last_tool_calls_performed = []
        self.record = []

    def get_function_definition(self, func_name: str) -> str:
        """
        Search for a function definition by its name.

        :param func_name: The name of the function to search for. If the function is a class method, do not include the class name—only specify the method’s name.
        :return: All matched function definitions (concatenated) or an error message if the func_name is not found.
        """
        orig_func_name = func_name
        if "::" in func_name:
            # If the function name contains a class name, we only want the method name
            func_name = func_name.split("::")[-1]
        if "." in func_name:
            # If the function name contains a module name, we only want the function name
            func_name = func_name.split(".")[-1]
        source_location = SourceLocation(function_name=func_name)

        functions_info = self.function_resolver.resolve_source_location(source_location)
        if not functions_info:
            func_name = "OSS_FUZZ_"+func_name
            source_location = SourceLocation(function_name=func_name)
            functions_info = self.function_resolver.resolve_source_location(source_location)
            if not functions_info:
                func_name = "_"+func_name
                source_location = SourceLocation(function_name=func_name)
                functions_info = self.function_resolver.resolve_source_location(source_location)
                if not functions_info:
                    return tool_error(f'No functions found with name {orig_func_name}')
        
        functions_in_scope = []
        for func_key, ranking_list in functions_info:
            functions_in_scope.append(func_key)

        if len(functions_in_scope) == 0:
            return tool_error(f'No functions found with name {func_name}')
        else:
            full_defs = []
            seen_defs = set()
            for func_key in functions_in_scope:
                path_and_code = self.function_resolver.get_code(func_key)
                code = path_and_code[-1]
                path = path_and_code[0]
                normalized = ''.join(code.split())
                file_then_code = f"[File: {path}]\n{code}"
                if normalized not in seen_defs:
                    seen_defs.add(normalized)
                    full_defs.append(file_then_code)

            return tool_success('\n\n'.join(full_defs))
