
import hashlib
import os
import json
import yaml
import subprocess

from agentlib.lib import tools

from .peek_utils import *

PeekLogsSkillGlobal = None

#########################
###### 💬 LLM Tool ######
#########################
@tools.tool
def show_log_at(log_file_path: str, offset: int, num_lines_to_show:int) -> str:
    """
    Open the log file and return its content.
    A total of num_lines_to_show lines will be shown starting from offset.
    There is a maximum of 100 lines that can be shown at once.
    You can display other lines in the log file by changing the offset.

    :param log_file_path: The path of the log file to open. The valid log paths have been provided to you.
    :param offset: The line number to start reading the log from.
    :return: num_lines_to_show lines of the log_file_path starting from the specified offset.
             More specifically, the output will be in the format:
             ```
             [File: <file_path> (<total_lines> lines total)]
             (<offset> lines above)
             <line_number>: <line_content>
             ...
             (<lines_below> lines below)
             ```
    """
    global PeekLogsSkillGlobal
    return PeekLogsSkillGlobal.show_log_at(log_file_path, offset, num_lines_to_show)


@tools.tool
def search_string_in_log(log_file_path: str, needle: str) -> str:
    """
    Search for a specific string in all files within the project.
    This tool can be used to search for specific variables names, types or functions etc...
    The needle MUST be a string with length greater than 3.
    The output format is <file_path>:<line_number>:<line_content>
    
    :param log_file_path: The path of the log file to search in. The valid log paths have been provided to you.
    :param needle: The string to search for.
    :return: A list of files containing the string and one line code that shows
             how the needle is used, or an error message if not found.
    """
    global PeekLogsSkillGlobal
    return PeekLogsSkillGlobal.search_string_in_log(log_file_path, needle)


#########################
##### 🧰 Tool Class #####
#########################
class PeekLogsSkill:
    def __init__(self, **kwargs):
        """
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        BIG FAT WARNING: THIS CLASS IS SHARED AMONG ALL THE AGENT INSTANCES.
        BE SUPER CAREFUL WHEN HOLDING STATE IN THIS CLASS, STUFF MIGHT HAVE TO 
        BE RESET WHEN YOU CREATE A NEW AGENT (e.g., THE TOOL CALLS GUARD)
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

        Initialize the PeekLogsSkillGlobal with necessary paths and generate the function mapping.

        Args:
            target_folder (str): Path to the target project folder.
            function_indices_path (str): Path to the JSON file containing function indices.
            functions_json_path (str): Path to the JSON directory containing function details.
            target_functions_by_commits_jsons_dir (str): Directory path for target functions by commits.
        """

        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        # The amount of matches we are returning when searching for a string in files
        self.MAX_FIND_IN_FILES_MATCHES = 10

        # This is the amount of tool calls we are keeping as "just done"
        # Basically if the LLM issues a tool call that was done in the last X calls, we tell 
        # it to try something else.
        self.DUPLICATE_TOOL_CALLS_GUARD_SIZE = 3
        self.last_tool_calls_performed = []

        global PeekLogsSkillGlobal
        PeekLogsSkillGlobal = self

    def clean_tool_call_history(self):
        self.last_tool_calls_performed = []

    def __add_to_tool_call_history(self, tool_call_id: str):
        """
        Add a tool call to the history.
        This is used to avoid repeating the same tool call in a short period of time.
        """
        if len(self.last_tool_calls_performed) > self.DUPLICATE_TOOL_CALLS_GUARD_SIZE:
            self.last_tool_calls_performed = self.last_tool_calls_performed[1:]
        self.last_tool_calls_performed.append(tool_call_id)

    def show_log_at(self, file_path:str, offset: int, num_lines: int) -> str:

        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"show_log_at:{file_path}:{offset}:{num_lines}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!") 
        else:
            self.__add_to_tool_call_history(tool_call_id)

        # Check if the file exists
        if not os.path.exists(file_path):
            return tool_error(f"File {file_path} does not exist.")

        file_view = ""

        with open(file_path, 'r') as file:
            log_context = file.read()
        
        # Grab the total number of lines in the file
        file_lines_tot = len(log_context.splitlines())

        num_lines_to_show = min(self.MAX_LINES_PER_VIEW, num_lines)

        # Grab the lines from offset to self.MAX_LINES_PER_VIEW
        file_lines_in_scope = log_context.splitlines()[offset:offset+num_lines_to_show]

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

    def search_string_in_log(self, file_path:str, needle: str) -> str:
        """
        Search for a string in the log.

        :param needle: The string to search for.
        :return: A list of line locations where the needle is found in the log.
        """
        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"search_string_in_log:{file_path}:{needle}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!") 
        else:
            self.__add_to_tool_call_history(tool_call_id)

        # Execute the ag command to search for the needle in the project folder
        if len(needle) < 4:
            return tool_error("The needle must be a string with length greater than 3 and less than 10.")

        # Check if the file exists
        if not os.path.exists(file_path):
            return tool_error(f"File {file_path} does not exist")

        search_result = []
        result = subprocess.run(['grep', "-n", str(file_path), needle], capture_output=True, text=True)
        result = result.stdout.splitlines()
        res_idx = 1
        for line in result[:self.MAX_FIND_IN_FILES_MATCHES]:
            if line:
                # TODO: Improve this...
                search_result.append(f" Match {res_idx}: {line}")
                res_idx+=1
        
        if len(search_result) == 0:
            return tool_error(f"No occurence of {needle} found in the log file.")
        else:
            search_result_report = ""
            search_result_report += f"Found {len(search_result)} occurences of {needle} in the log file:\n"
            for line in search_result:
                search_result_report += f"{line}\n"

            return tool_success(search_result_report)