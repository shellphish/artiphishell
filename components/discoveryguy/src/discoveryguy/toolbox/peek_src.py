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

from .peek_utils import tool_error, tool_success, tool_choice

from ..utils import do_grep, show_lines
from ..config import Config


log = logging.getLogger("discoveryguy.peek_src")

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
def lookup_symbol(expression: str) -> str:
    """
    Search the target source files for a specific expression using grep. The expression should be related to the conditions/functions that can help to reach the sink function.

    Constructs and runs `grep -rnE <expression>` (or `-rniE`/`-rhiE` when context is zero/non-zero)
    in the project directory and returns all matching lines. Use this to find function definitions,
    variable usages, conditional statements, etc.

    Because grep interprets special characters, you must escape any regex metacharacters
    (e.g., backslashes, quotes, brackets) in `expression` so they're passed correctly to the shell.

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
    def __init__(self, cp, **kwargs):

        # This is a cp BUILT with debug artifacts
        self.cp = cp

        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        self.function_resolver = kwargs["function_resolver"]
        self.function_indices_path = kwargs["function_index"]
        self.analysis_graph_api = kwargs["analysis_graph_api"]

        self.project_source = kwargs["project_source"]

        self.codeql_initialized = False
        self.record = []
        self.no_match_count = 0

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

    def get_functions_by_file(self, file_path: str, page: int) -> str:
        """
        Given a file path, return the functions definitions in that file.
        """
        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"get_functions_by_file:{file_path}:{page}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} tool calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!")
        else:
            self.__add_to_tool_call_history(tool_call_id)

        file_path = file_path.lstrip('/')

        functions_info = list(self.function_resolver.find_by_filename(file_path))
        if len(functions_info) == 0:
            return tool_error(f'The file {file_path} does not exist or it is out of scope!')

        # Verify that the functions are in scope
        functions_in_scope = []
        for func_key in functions_info:
            func_index:FunctionIndex = self.function_resolver.get(func_key)
            if func_index.was_directly_compiled:
                functions_in_scope.append(func_key)

        if len(functions_in_scope) == 0:
            return tool_error(f'No functions found in file {file_path} that are in scope!')

        total_pages = (len(functions_in_scope) + self.MAX_FUNCTIONS_PER_PAGE - 1) // self.MAX_FUNCTIONS_PER_PAGE
        paged_functions_info = functions_in_scope[self.MAX_FUNCTIONS_PER_PAGE*(page-1):self.MAX_FUNCTIONS_PER_PAGE*page]

        functions_report = ''

        if len(paged_functions_info) == 0:
            return tool_error(f'No functions found in page {page} for file {file_path}')
        else:
            functions_report += f'Found a total of {len(functions_in_scope)} functions in file {file_path}\n'
            functions_report += f'Page: {page}\n'
            functions_report += 'Filename:StartLine:StartColumn::Signature\n'
            functions_report += '\n'.join(functions_in_scope)
            functions_report += f'\nTotal Pages: {total_pages}'
            return tool_success(functions_report)

    def show_file_at(self, file_path: str, offset: int, num_lines: int) -> str:

        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"show_file_at:{file_path}:{offset}:{num_lines}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!")
        else:
            self.__add_to_tool_call_history(tool_call_id)

        file_view = ""

        # Making sure that the file_path is relative!
        # This path is ALWAYS relative to the source-root
        file_path = file_path.lstrip('/')

        # Get the file with the function resolver
        # NOTE: this check ensures that the LLM did not hallucinate a name
        functions_info = list(self.function_resolver.find_by_filename(file_path))
        if len(functions_info) == 0:
            return tool_error(f'The file {file_path} does not exist or it is out of scope!')

        # NOTE: Verify that the functions in that file are in scope.
        #       We can technically simplify this by using the focus_repo_rel_path attribute in OSSFuzzProject.
        functions_in_scope = []
        for func_key in functions_info:
            func_index:FunctionIndex = self.function_resolver.get(func_key)
            # NOTE: for discoveryGuy, we only need to check if the file was directly
            #       compiled or not, it is fine since we are not modifying the source code,
            #       but we simply have to reason about it.
            #if func_index.was_directly_compiled:
            functions_in_scope.append(func_key)

        if len(functions_in_scope) == 0:
            return tool_error(f'No functions found in file {file_path} that are in scope! Do not consider it for your investigation.')

        relative_file_path = str(self.function_resolver.get(functions_in_scope[0]).target_container_path).lstrip("/")

        # NOTE: if it does not, something might be wrong with the function resolver or the file
        # path that are passed to the
        if not relative_file_path.startswith("src/"):
            return tool_error(f'The file cannot be found, search somewhere else...')

        # NOTE: change the first occurence of src/ to built_src/
        #       this is the format we expect and create in the the run.sh scripts.
        relative_file_path = relative_file_path.replace("src/", "built_src/", 1)

        # NOTE: discoveryGuy can look anywhere (even in paths that are not in scope).
        #       this is because it doesn't need to modify the files.
        #       /artifacts/built_src is guaranteed to exists!
        full_file_path = os.path.join(self.cp.project_path, "artifacts", relative_file_path)

        if not os.path.exists(full_file_path):
            return tool_error(f"File {full_file_path} does not exist or it is out of scope.")
        elif not os.path.isfile(full_file_path):
            return tool_error(f"{full_file_path} is not a file.")
        else:
            with open(full_file_path, 'r') as file:
                file_context = file.read()

        # Grab the total number of lines in the file
        file_lines_tot = len(file_context.splitlines())

        num_lines_to_show = min(self.MAX_LINES_PER_VIEW, num_lines)

        # Grab the lines from offset to self.MAX_LINES_PER_VIEW
        file_lines_in_scope = file_context.splitlines()[offset:offset+num_lines_to_show]

        # If we have no lines left, tell it to the llm.
        if len(file_lines_in_scope) == 0:
            return tool_error("No more lines to show.")

        file_lines_in_scope = '\n'.join(file_lines_in_scope)

        # Building the view!
        file_view = f"\n[File: {file_path} ({file_lines_tot} lines total)]\n"
        file_view += f"({offset} lines above)\n"

        # Add the lines we are showing, add the line numbers at the beginning
        for idx, line in enumerate(file_lines_in_scope.splitlines()):
            idx = idx + offset
            file_view += f"{idx + 1}: {line}\n"

        # Finally, added the remaining line
        lines_below = file_lines_tot - (offset + num_lines_to_show)
        if lines_below > 0:
            file_view += f"({lines_below} lines below)\n"
            with open(full_file_path, 'r') as file:
                file_context = file.read()

        # Grab the total number of lines in the file
        file_lines_tot = len(file_context.splitlines())

        num_lines_to_show = min(self.MAX_LINES_PER_VIEW, num_lines)

        # Grab the lines from offset to self.MAX_LINES_PER_VIEW
        file_lines_in_scope = file_context.splitlines()[offset:offset+num_lines_to_show]

        # If we have no lines left, tell it to the llm.
        if len(file_lines_in_scope) == 0:
            return tool_error("No more lines to show.")

        file_lines_in_scope = '\n'.join(file_lines_in_scope)

        # Building the view!
        file_view = f"\n[File: {file_path} ({file_lines_tot} lines total)]\n"
        file_view += f"({offset} lines above)\n"

        # Add the lines we are showing, add the line numbers at the beginning
        for idx, line in enumerate(file_lines_in_scope.splitlines()):
            idx = idx + offset
            file_view += f"{idx + 1}: {line}\n"

        # Finally, added the remaining line
        lines_below = file_lines_tot - (offset + num_lines_to_show)
        if lines_below > 0:
            file_view += f"({lines_below} lines below)\n"
        else:
            file_view += f"(No lines below)\n"

        return file_view

    def check_coverage_for_line(self, file_path: str, line_number: int) -> str:
        """
        Check if a file line was hit during execution.

        :param file_path: The path of the file to check.
        :param line_number: The line number to check.
        :return: True if the line was hit, False otherwise.
        """
        # Check if the file_path is in the coverage data
        if file_path in self.coverage_data:
            # Check if the line_number is in the list of lines hit
            if line_number in self.coverage_data[file_path]:
                return "The line was covered!"
            else:
                return "This specific line was NOT covered!"
        else:
            return "The line was NOT covered! Actually, the entire file was not covered!"

    def search_function(self, func_name: str) -> str:
        """
        Search for a function by its name.

        :param func_name: The name of the function to search for.
        :return: A list of matches with file name and line numbers or an error message if the func_name is not found.
        """

        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"search_function:{func_name}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!")
        else:
            self.__add_to_tool_call_history(tool_call_id)

        functions_info = list(self.function_resolver.find_by_funcname(func_name))

        functions_in_scope = []
        for func_key in functions_info:
            func_index:FunctionIndex = self.function_resolver.get(func_key)
            #if func_index.focus_repo_relative_path:
            functions_in_scope.append(func_key)

        functions_info = functions_in_scope

        if len(functions_info) == 0:
            return tool_error(f'No functions found with name {func_name}')
        else:
            functions_report = ''
            functions_report += f' {len(functions_info)} functions found:\n'
            functions_report += 'Function File Path:StartLine:StartColumn::Function Signature\n'
            functions_report += '\n'.join(functions_info)
            return tool_success(functions_report)

    def code_too_long(self, code: str) -> str:
        if len(code)  > 50000:
            return True
        else:
            return False


    def lookup_symbol(self, expression: str) -> str:
        # TODO:
        '''
        Rank matched functions
        '''
        analysis_graph_alive = True
        tool_call_id = hashlib.md5(f"search_function:{expression}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            raise RuntimeError(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!")
        else:
            self.__add_to_tool_call_history(tool_call_id)

        if "main" in expression or "harness" in expression or "fuzz" in expression:
            raise RuntimeError("This query is too generic. Please refine and be more specific in your expression (look at variables and symbols. If you saw this too many times, you should stop thinking and generate the report.")

        stdout1 = do_grep(0, self.project_source, expression)
        if stdout1 == "":
            self.no_match_count += 1
            if self.no_match_count > 30:
                raise RuntimeError("You have been keeping using matching nothing for too many times. You MUST finish your analysis and generate the report.")
            else:
                return f"No matches found (attempt {self.no_match_count}). Try a different expression. After 15 unsuccessful attempts, consider wrapping up your analysis and generating the report.\n"
        matches = stdout1.split("--\n")
        matched_function_index = []
        matched_variables = {}
        for match in matches:
            try:
                tmp = match.split(":")
            except Exception as e:
                log.error(f"Error parsing match: {match} - {e}")
                continue
            filename = tmp[0].lstrip(".")
            line = int(tmp[1])
            maybe_global = True
            indexes = self.function_resolver.find_by_filename(filename)
            for index in indexes:
                boundary = self.function_resolver.get_function_boundary(index)
                if boundary[0] <= line <= boundary[1]:
                    matched_function_index.append(index)
                    maybe_global = False
                    break

            if maybe_global:
                try:
                    res = self.analysis_graph_api.get_global_variable_usage(filename)
                except Exception as e:
                    log.warning(f"Error getting global variable usage for {filename}: {e}")
                    analysis_graph_alive = False
                    # FIXME: is this exception caught by agentlib or this is allowed?
                    res = []
                if analysis_graph_alive == True:
                    if len(res) > 0:
                        global_id = f"{filename}:{line}"
                        # global_vars = do_grep(10, self.project_source, expression)
                        global_vars = show_lines(self.project_source, filename, line, 10)
                        matched_variables[global_id] = global_vars
                    else:
                        # If no global variables are found, we can still grep the file
                        # to find any other matches that are not functions or globals.
                        matched_id = f"{filename}:{line}"
                        matched_vars = show_lines(self.project_source, filename, line, 1)
                        matched_variables[matched_id] = matched_vars
                else:
                    global_id = f"{filename}:{line}"
                    global_vars = do_grep(10, self.project_source, expression)
                    matched_variables[global_id] = global_vars

        log.info(f"Matched {len(matched_function_index)} functions and {len(matched_variables)} global variables for expression: {expression}")
        function_code = ""
        for index in set(matched_function_index):
            if index in self.record:
                function_code += f"\n I have shown you this function ({index}) before.\n"
                continue
            tmp_code = self.function_resolver.get_code(index)[-1]
            function_code += tmp_code + "\n"
            if self.code_too_long(function_code):
                function_code = ""
                matched_function_index = []


        global_code = ""
        for global_id in set(matched_variables):
            if global_id in self.record :
                global_code += f"\n I showed you this variable({global_id}) before\n"
                continue
            global_var = matched_variables[global_id]
            global_code += global_var + "\n"
            if self.code_too_long(global_code):
                global_code = ""
                matched_variables = []

        code = function_code+ "\n\n" + global_code
        if self.code_too_long(code):
            matched_function_index = []
            matched_variables = []
            return "This is a bad pattern, it matches too many lines of code. Please refine your expression to be more specific. Don't use this expression again."

        if len(matched_function_index) == 0 and matched_variables == 0:
            return "No matches found for the expression. Don't use this expression again."
        else:
            self.record = list(set(self.record) | set(matched_function_index) | set(matched_variables))
            return tool_success(code)
