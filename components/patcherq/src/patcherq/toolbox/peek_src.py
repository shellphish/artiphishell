

import os
import json
import subprocess
import yaml
import hashlib 
import logging

from typing import Optional, Dict, Any, List, Union
from pathlib import Path
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex

from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, FunctionResolver

from difflib import SequenceMatcher
from agentlib.lib import tools

from .peek_utils import *
from ..config import Config


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PeekSrcSkillGlobal = None

#########################
###### 💬 LLM Tool ######
#########################
@tools.tool
def show_file_at(file_path: str, offset: int, num_lines_to_show:int) -> str:
    """
    Open a file and return its content.
    A total of num_lines_to_show lines will be shown starting from offset.
    There is a maximum of 100 lines that can be shown at once.
    You can display other lines in the file by changing the offset.
    Open a file and return its content.

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
def get_functions_by_file(file_path: str, page: int) -> str:
    """
    Given a file path, return the function definitions in that file in paginated form.
    There are a total 20 functions that can be shown per page. If you need to see more functions, you can change the page number.
    :param file_path: The path of the file to search for functions.
    :param page: The page to display starting from 1.
    :return: A list of functions in the file or an error message if not found.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.get_functions_by_file(file_path, page)


@tools.tool
def search_string_in_file(file_path:str, needle: str, page: int) -> str:
    """
    Search for a specific string in a given file.
    The output is paginated.
    This tool can be used to search for specific variables names, types or functions etc...
    The needle MUST be a string with length greater than 3.
    IMPORTANT: Searching the entire codebase is FORBIDDEN.
    The output format is Match <N>:<line_number>:<line_content>
    
    :param file_path: The path of the file to search in.
    :param needle: The string to search for.
    :param page: The page to display starting from 1.
    :return: A list matches in the file or an error message if not found.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.search_string_in_file(file_path, needle, page)

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
def get_function_or_struct_location(name: str) -> str:
    """
    Search for a function or struct by its name.

    :param name: The name of the function or struct to search for.
    :return: A list of matches with file name and line numbers or an error message if the symbol is not found.
    """
    global PeekSrcSkillGlobal
    return PeekSrcSkillGlobal.get_function_or_struct_location(name)

#########################
##### 🧰 Tool Class #####
#########################
class PeekSrcSkill:

    def __init__(self, function_resolver=None,  **kwargs):
        """
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        BIG FAT WARNING: THIS CLASS IS SHARED AMONG ALL THE AGENT INSTANCES.
        BE SUPER CAREFUL WHEN HOLDING STATE IN THIS CLASS, STUFF MIGHT HAVE TO 
        BE RESET WHEN YOU CREATE A NEW AGENT (e.g., THE TOOL CALLS GUARD)
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

        Initialize the PeekRepoSkill with necessary paths and generate the function mapping.

        Args:
            target_folder (str): Path to the target project folder.
            function_indices_path (str): Path to the JSON file containing function indices.
            functions_json_path (str): Path to the JSON directory containing function details.
            target_functions_by_commits_jsons_dir (str): Directory path for target functions by commits.
            
            CodeQl and LangServer Stuff
            project_name (str): The name of the codeql project.
            project_language (str): The language of the codeql project.
            project_id (str): The id of the codeql project.
            codeql_db_path (str): The path to the codeql database. Required for local run.            
        """
        use_task_service = False if 'use_task_service' not in kwargs else kwargs['use_task_service']

        with open(kwargs['project_yaml'], "r") as f:
            self.project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        self.cp = OSSFuzzProject(
                                 oss_fuzz_project_path=Path(kwargs['target_root']),
                                 project_source=Path(kwargs['source_root']),
                                 augmented_metadata=self.project_metadata,
                                 use_task_service=use_task_service
                                )

        # Function index stuff
        self.functions_by_file_index = kwargs['functions_by_file_index']
        with open(self.functions_by_file_index, 'r') as f:
            self.functions_by_file_index = json.load(f)
            
        self.function_indices_path = kwargs['function_index']
        
        with open(self.function_indices_path, 'r') as f:
            self.function_indices = json.load(f)

        # Function resolver object
        self.function_resolver = function_resolver
        
        # The amount of functions we are returning in page
        self.MAX_FUNCTIONS_PER_PAGE = 20
        
        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        # The amount of matches we are returning when searching for a string in files
        self.MAX_FIND_IN_FILES_MATCHES = 10

        # The amount of lines we are returning once we open a file
        self.MAX_LINES_PER_VIEW = 100

        # The amount of matches we are returning when searching for a string in files
        self.MAX_FIND_IN_FILES_MATCHES = 10
        
        self.codeql_initialized = False
        self.langserver_initialized = False
        
        # Try to init 3rd party tools and set the config to false if they are not available
        if Config.use_codeql_server:
            from . import CodeQlSkill
            self.codeql = CodeQlSkill(function_resolver=self.function_resolver, **kwargs)
            Config.use_codeql_server = self.codeql.initialized
            
        if Config.use_lang_server:
            from . import LangServerSkill
            self.langserver = LangServerSkill(project_source=self.cp.project_source, **kwargs)
            Config.use_lang_server = self.langserver.initialized

        # This is the amount of tool calls we are keeping as "just done"
        # Basically if the LLM issues a tool call that was done in the last X calls, we tell 
        # it to try something else.
        self.DUPLICATE_TOOL_CALLS_GUARD_SIZE = 3
        self.last_tool_calls_performed = []

        # Finally, setting the global variable
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

    def search_string_in_file(self, file_path:str, needle: str, page: int) -> str:
        """
        Search for a specific string in a given file.
        This tool can be used to search for specific variables names, types or functions etc...
        The needle MUST be a string with length greater than 3.
        The output format is Match <N>:<line_number>:<line_content>

        :param file_path: The path of the file to search in.
        :param needle: The string to search for. DO NOT use whitespace, the needle MUST be a single word.
        :param page: If we need to skip some matches, we can use this to offset the search.
        :return: A list of matches in the file or an error message if not found.
        """
        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"search_string_in_file:{file_path}:{needle}:{page}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} tool calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!") 
        else:
            self.__add_to_tool_call_history(tool_call_id)

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
        
        # Execute the ag command to search for the needle in the project folder
        if len(needle) < 4:
            return tool_error("The needle must be a string with length greater than 3 and less than 10.")
        
        search_result = []

        if not os.path.exists(full_file_path):
            return tool_error(f"The requested file '{full_file_path}' does not exist or it is out of scope.")

        result = subprocess.run(['ag', "-Q", "--nogroup", "--silent", needle, str(full_file_path)], capture_output=True, text=True)
        result = result.stdout.splitlines()
        res_idx = (page-1)*self.MAX_FIND_IN_FILES_MATCHES+1
        tot_matches = len(result)
        total_pages = (tot_matches + self.MAX_FIND_IN_FILES_MATCHES - 1) // self.MAX_FIND_IN_FILES_MATCHES
        paged_result = result[self.MAX_FIND_IN_FILES_MATCHES*(page-1):self.MAX_FIND_IN_FILES_MATCHES*page]

        for line in paged_result:
            if line:
                search_result.append(f" Match {res_idx}: {line}")
                res_idx+=1
        
        if len(search_result) == 0:
            return tool_error(f"No occurence of {needle} found in {file_path}.")
        else:
            search_result_report = ""
            search_result_report += f"Found {tot_matches} occurences of {needle} in {file_path}:\nPage: {page}\n"
            for line in search_result:
                search_result_report += f"{line}\n"
            search_result_report += f"Total Pages: {total_pages}"
            
            return tool_success(search_result_report)

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
            # NOTE: we want ONLY functions in the focused repo
            if func_index.focus_repo_relative_path:
                functions_in_scope.append(func_key)

        if len(functions_in_scope) == 0:
            return tool_error(f'No functions found with name {func_name}')
        else:
            functions_report = ''
            functions_report += f'{len(functions_in_scope)} functions found:\n'
            functions_report += 'Filename:StartLine:StartColumn:Signature\n'
            entry = ''
            for func_key_in_scope in functions_in_scope:
                func_in_scope = self.function_resolver.get(func_key_in_scope)
                entry += f'{func_in_scope.focus_repo_relative_path}:{func_in_scope.start_line}:{func_in_scope.start_column}:{func_in_scope.signature}'
                entry += "\n"
            functions_report += entry
            return tool_success(functions_report)
        
    def get_function_or_struct_location(self, symbol_name: str) -> str:
        """
        Search for a symbol definition by its name.
        You can use this to search for definitions of structs and functions only.

        :param symbol_name: The name of the symbol to search for.
        :return: A list of matches with file name and line numbers or an error message if the symbol_name is not found.
        """

        # TOOL CALL GUARD 💂🏼
        tool_call_id = hashlib.md5(f"get_function_or_struct_location:{symbol_name}".encode()).hexdigest()
        if tool_call_id in self.last_tool_calls_performed:
            return tool_error(f"You performed the same tool call (with the same arguments!) very recently (less than {self.DUPLICATE_TOOL_CALLS_GUARD_SIZE} calls ago), this might indicate an error in your reasoning. Just reuse the old results and avoid to call this tool again!") 
        else:
            self.__add_to_tool_call_history(tool_call_id)

        are_there_functions = False
        are_there_structs = False
        functions_report = ''
        structs_report = ''
        
        # First we search for functions
        functions_info = self.search_function(symbol_name)
        if "[ERROR]" not in functions_info:
            are_there_functions = True
            functions_report = functions_info
        
        # Now we search for structs
        if Config.use_codeql_server:
            structs_info = self.codeql.get_struct_definition_location(symbol_name)
            if "[ERROR]" not in structs_info:
                are_there_structs = True
                structs_report = structs_info
                
        if not are_there_functions and not are_there_structs:
            if Config.use_codeql_server:
                return tool_error(f'No functions or structs found with name {symbol_name}')
            else:
                return tool_error(f'No functions found with name {symbol_name} and struct search could not be performed. You can try search_string_in_file tool as an alternative.')
        else:
            report = ''
            if are_there_functions:
                report += f"Functions:\n{functions_report}\n"
            if are_there_structs:
                report += f"Structs:\n{structs_report}\n"
            return tool_success(report)
