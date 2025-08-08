import os
import json
import logging
import hashlib

from agentlib.lib import tools

from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver
from analysis_graph.models.cfg import CFGFunction
from shellphish_crs_utils.models.coverage import FileCoverageMap, FunctionCoverageMap

log = logging.getLogger("sarifguy.peek_src")
logger = log

PeekSrcSkillGlobal = None


def tool_error(message: str):
    """
    Print an error message and return it as a string.

    Args:
        message (str): The error message to print.

    Returns:
        str: The error message.
    """
    log.error("[ERROR]: %s", message)
    return message


def tool_success(message: str):
    """
    Print a success message and return the result

    Args:
        message (str): The result

    Returns:
        str: The success message.
    """
    log.info("[SUCCESS]: %s", message)
    return message


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


class PeekSrcSkill:
    def __init__(self, cp, **kwargs):
        
        # This is a cp BUILT with debug artifacts
        self.cp = cp
        
        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100
        
        self.function_resolver = kwargs["function_resolver"]

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
            if func_index.focus_repo_relative_path:
                # NOTE: add the func_key of all the functions in scope
                functions_in_scope.append(func_key)
        
        if len(functions_in_scope) == 0:
            return tool_error(f'No functions found in file {file_path} that are in scope!')

        file_path = str(self.function_resolver.get(functions_in_scope[0]).focus_repo_relative_path).lstrip("/")
        total_pages = (len(functions_in_scope) + self.MAX_FUNCTIONS_PER_PAGE - 1) // self.MAX_FUNCTIONS_PER_PAGE
        paged_functions_info = functions_in_scope[self.MAX_FUNCTIONS_PER_PAGE*(page-1):self.MAX_FUNCTIONS_PER_PAGE*page]
        
        functions_report = ''
        
        if len(paged_functions_info) == 0:
            return tool_error(f'No functions found in page {page} for file {file_path}')
        else:
            functions_report += f'There are a total of {len(functions_in_scope)} functions defined in file {file_path}\n'
            functions_report += f'Page: {page}\n'
            functions_report += 'Filename:StartLine:StartColumn::Signature\n'
            entry = ''
            for func_key_in_scope in paged_functions_info:
                func_in_scope = self.function_resolver.get(func_key_in_scope)
                entry += f'{func_in_scope.focus_repo_relative_path}:{func_in_scope.start_line}:{func_in_scope.start_column}:{func_in_scope.signature}\n'
            functions_report += entry
            functions_report += f'\nTotal Pages: {total_pages}\n'
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

        if len(functions_info) != 0:
            functions_in_scope = []
            for func_key in functions_info:
                func_index:FunctionIndex = self.function_resolver.get(func_key)
                if func_index.focus_repo_relative_path:
                    functions_in_scope.append(func_key)

            # NOTE: if we have it in the func indexer, but no functions are in scope, we can safely skip this.
            if len(functions_in_scope) == 0:
                return tool_error(f'No functions found in file {file_path} that are in scope! Do not consider it for your investigation.')

            # NOTE: the file_path is relative to the focused repo.
            file_path = str(self.function_resolver.get(functions_in_scope[0]).focus_repo_relative_path).lstrip("/")
        else:
            # Maybe that is a .h that we do not have in the function resolver?
            # FIXME: recover from this, we can get the basename and do a find to see if that file
            # exists in the focused repo path.
            # FIXME: we might want to allow only to specific type of files here.
            # results = find('/focus/report/path', name=os.path.basename(file_path), type='f')
            logger.info("🫡 Cannot find the file in the function resolver, using the file path as it is.")

        full_file_path = os.path.join(self.cp.project_source, file_path)

        if not os.path.exists(full_file_path):
            return tool_error(f"File {full_file_path} does not exist or it is out of scope. You MUST Stop trying to access it.")
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