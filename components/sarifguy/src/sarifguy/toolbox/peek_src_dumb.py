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

logger = logging.getLogger("sarifguy.peek_src_dumb")
logger.setLevel(logging.INFO)
log = logger

PeekDumbSrcSkillGlobal = None


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
    global PeekDumbSrcSkillGlobal
    return PeekDumbSrcSkillGlobal.get_functions_by_file(file_path)


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
    global PeekDumbSrcSkillGlobal
    return PeekDumbSrcSkillGlobal.show_file_at(file_path, offset, num_lines_to_show)


@tools.tool
def search_function(func_name: str) -> str:
    """
    Search for a function by its name.
    This tool can be used to retrieve the location of a function definition in the project.

    :param func_name: The name of the function to search for.
    :return: A list of matches with file name and line numbers or an error message if the func_name is not found.
    """
    global PeekDumbSrcSkillGlobal
    return PeekDumbSrcSkillGlobal.search_function(func_name)


class PeekSrcSkillDumb:
    def __init__(self, cp, **kwargs):
        
        # This is a cp BUILT with debug artifacts
        self.cp = cp
        
        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        # This is the amount of tool calls we are keeping as "just done"
        # Basically if the LLM issues a tool call that was done in the last X calls, we tell 
        # it to try something else.
        self.DUPLICATE_TOOL_CALLS_GUARD_SIZE = 3
        self.last_tool_calls_performed = []

        global PeekDumbSrcSkillGlobal
        PeekDumbSrcSkillGlobal = self

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