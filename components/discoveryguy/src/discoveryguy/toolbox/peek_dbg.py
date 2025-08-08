import pprint
import logging
import os
import yaml
import re

from pathlib import Path
from typing import Dict, Any, List, Tuple, Union
from dataclasses import dataclass
from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.models.crs_reports import RootCauseReport
from agentlib import tools
from shellphish_crs_utils.models import POIReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from crs_telemetry.utils import get_otel_tracer, get_current_span
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver

log = logging.getLogger("peek_dbg")
tracer = get_otel_tracer()

PeekGDBSkillGlobal = None

#########################
###### 💬 LLM Tool ######
#########################


@tools.tool
def check_coverage_for(file_name: str, line_number: int) -> str:
    """
    This tool checks if a file line was hit during the execution of the 
    latest input.
    :param file_name: The name of the source file to analyze.
    :param line_number: The line number in the src_file to check.
    :returns: str, a message indicating if the line was hit or not. If the line was not hit, the tool returns the ranges of line covered in the file. If no line was hit in that file, we return an error message.
    """
    global PeekGDBSkillGlobal
    return PeekGDBSkillGlobal.check_coverage_for(file_name, line_number)


@tools.tool
def check_value_of_variable_at(file_name: str, line_number: int, var_name: str) -> str:
    """
    This tool returns the value of a variable at a specific line in a file during the 
    execution of the latest input.
    :param file_name: The name of the source file to analyze.
    :param line_number: The line number in the src_file to check.
    :param var_name: The name of the variable to check.
    :returns: str, which is the value of the variable at the specific line in the file, or 
                a message indicating an error finding the variable.
    """
    global PeekGDBSkillGlobal
    return PeekGDBSkillGlobal.check_value_of_variable_at(file_name, line_number, var_name)

@tools.tool
def coverage_pagination(page: int = 0, page_size: int = 10) -> List[Dict[str, Any]]:
    """
    This tool paginates the coverage data for the current project.
    :param page: The page number to retrieve.
    :param page_size: The number of items per page.
    :returns: A list of dictionaries containing the coverage data for the requested page.
    """
    global PeekGDBSkillGlobal
    return PeekGDBSkillGlobal.coverage_pagination(page, page_size)

@tools.tool
def get_dynamic_coverage(depth: int = 3) -> str:
    """
    This tool gives information about the call trace that the program executed when running the previous seed. 
    It will give you by default the last 3 functions in the call stack from a given VERIFIED frontier node, 
    but you can specify how many functions you want to see using depth.
    :param depth: The number of functions to trace backwards.
    :returns: str, the coverage information of the last depth functions starting from the frontier node.
    """
    global PeekGDBSkillGlobal
    return PeekGDBSkillGlobal.get_dynamic_coverage(depth)


#########################
##### 🧰 Tool Class #####
#########################
class PeekDBGSkill:
    def __init__(
                 self, 
                 oss_fuzz_project: OSSFuzzProject, 
                 func_resolver: Union[LocalFunctionResolver, RemoteFunctionResolver],
                ):
        
        self.oss_fuzz_project = oss_fuzz_project
        self.func_resolver = func_resolver

        # We are storing here the coverage data
        # This is a dictionary like:
        # The filename is in the focus repo.
        # {'cups/raster-interpret.c': [509, 510, 511]}
        self.coverage_data = None
        self.coverage_data_list = None
        self.dynamic_coverage = None
        self.frontier_nodes = None

        global PeekGDBSkillGlobal
        PeekGDBSkillGlobal = self

    def set_coverage_data(self, coverage_data):
        """
        Set the coverage data for the current project.
        This is used to check if a file line was hit
        """
        self.coverage_data = coverage_data
        self.coverage_data_list = list(coverage_data.keys())

    def set_dynamic_coverage(self, dynamic_coverage):
        """
        Set the dynamic coverage function from Pintracer of the last seed. 
        """
        self.dynamic_coverage = dynamic_coverage

    def set_debugger(self, dyva_debugger):
        """
        Set the debugger for the current project.
        """
        self.dyva_debugger = dyva_debugger

    def set_frontier_nodes(self, frontier_nodes):
        """
        Set the possible set of frontier nodes for the current project.
        This is later used to check and find which ones are actually reached.
        """
        if self.coverage_data is None:
            log.critical("The coverage data is not set. Please set the coverage data before using this tool.")
            assert(False)

        possible_frontiers = [] 
        for (x, y) in frontier_nodes:
            info = self.func_resolver.get(x.identifier)
            file_path = str(info.target_container_path)
            func_name = info.funcname
            possible_frontiers.append((file_path, func_name, x, y))

        real_frontiers = set()
        return_real_frontier_nodes = []
        for file_name, func_name, _x, _y in possible_frontiers:
            for k in self.coverage_data.keys():
                if file_name in k:
                    if func_name in self.coverage_data[k].keys():
                        if (file_name, func_name) not in real_frontiers:
                            real_frontiers.add((file_name, func_name))
                            return_real_frontier_nodes.append((_x,_y))
                    
        # these are verified to actually exist in the coverage data
        self.frontier_nodes = list(real_frontiers)

        # return this so that we can give the LLM direct feedback
        return return_real_frontier_nodes


    def get_dynamic_coverage(self, depth: int = 3) -> str:
        """
        This tool gives information about the call trace that the program executed when running the previous seed. 
        It will give you by default the last 3 functions in the call stack from a given VERIFIED frontier node, 
        but you can specify how many functions you want to see using depth.
        :param depth: The number of functions to trace backwards.
        :returns: str, the coverage information of the last depth functions starting from the frontier node.
        """
        if self.dynamic_coverage is None:
            log.warning("No dynamic coverage data available.")
            return "No dynamic coverage data available."
        
        # grabbing just the first frontier node for funsies: probably need to change this later
        if self.frontier_nodes is None:
            log.warning("No frontier nodes set.")
            return "No frontier nodes set. Please set the frontier nodes before using this tool."
        
        log.info(f"Using frontier nodes: {self.frontier_nodes[0]}")
        frontier = self.frontier_nodes[0]

        start = len(self.dynamic_coverage[0]) - 1  # if we can't find the frontier, we will just start from the end
        for i in range(len(self.dynamic_coverage[0])):
            if frontier[0] in self.dynamic_coverage[0][i]['Symbol'][0]['FileName']  and \
               self.dynamic_coverage[0][i]['Symbol'][0]['FunctionName'] == frontier[1]:
                start = i
                break

        dynamic_data = ""
        tries = 0
        while tries < depth:
            if start < 0:
                break

            file_name = self.dynamic_coverage[0][start]['Symbol'][0]['FileName']
            func_name = self.dynamic_coverage[0][start]['Symbol'][0]['FunctionName']

            if file_name == '':
                start -= 1
                break
            try:
                lines = self.coverage_data[file_name][func_name]
                intervals = self._list_to_intervals(lines)
                dynamic_data += f"{start}. Function: {func_name}, File: {file_name}, Lines: {intervals}\n"
            except:
                # TODO: THIS SHOULD NEVER HAPPEN???
                log.error(f"Function {func_name} in file {file_name} not found in coverage data.")
                start -= 1
                continue
                # dynamic_data += f"{i}. Function: {func_name}, File: {file_name}, Lines: N/A\n"
            
            start -= 1
            tries += 1

        return dynamic_data

    def coverage_pagination(self, page: int = 0, page_size: int = 10) -> str:
        """
        Paginate the coverage data for the current project.
        :param page: The page number to retrieve.
        :param page_size: The number of items per page.
        :returns: A list of dictionaries containing the coverage data for the requested page.
        """
        if self.coverage_data is None:
            log.critical("The coverage data is not set. Please set the coverage data before using this tool.")
            return "The coverage data is not set. Please set the coverage data before using this tool."

        start = page * page_size
        end = start + page_size
        paginated_data = ""

        if start >= len(self.coverage_data_list):
            log.warning(f"Requested page {page} is out of range. Returning empty data.")
            return f"Requested page {page} is out of range. Returning empty data: {paginated_data}"

        for i in range(start, end):
            if i >= len(self.coverage_data_list):
                break
            file_name = self.coverage_data_list[i]
            paginated_data += f"Covered File: {file_name} \n "
            for func in self.coverage_data[file_name].keys():
                lines = self.coverage_data[file_name][func]
                intervals = self._list_to_intervals(lines)
                paginated_data += f"Covered Function: {func}, Lines: {intervals}\n"
            paginated_data += "\n \n"

        return paginated_data

    def check_coverage_for(self, file_name: str, line_number: int) -> str:
        """
        Check if a file line was hit during
        the execution of the latest input.
        :param file_name: The name of the source file to analyze.
        :param line_number: The line number in the src_file to check.
        :returns: str, a message indicating if the line was hit or not.
        """
        if self.coverage_data is None:
            log.critical("The coverage data is not set. Please set the coverage data before using this tool.")
            assert(False)
        
        if file_name not in self.coverage_data:
            return f"None of the line in file {file_name} was covered during the execution of the input."
        
        for func in self.coverage_data[file_name].keys():
            if line_number in self.coverage_data[file_name][func]:
                return f"The line {line_number} was hit during the execution of the last input."
        
        covered_ranges = []
        for func in self.coverage_data[file_name].keys():
            lines = self.coverage_data[file_name][func]
            covered_ranges += self._list_to_intervals(lines)
        feedback = ''
        feedback += f"The line {line_number} was not hit during the execution of the last input."
        feedback += f'You MUST select a line within on of the following ranges: {", ".join(covered_ranges)}'
        
        log.info(f"Feedback: {feedback}")

        return feedback
        
    
    def check_value_of_variable_at(self, file_name: str, line_number: int, var_name: str) -> str:
        """
        Check the value of a variable at a specific line in a file during runtime.
        :param file_name: The name of the source file to analyze.
        :param line_number: The line number in the src_file to check.
        :param var_name: The name of the variable to check.
        :returns: str, a message indicating if the variable was found or not.
        """

        # Check if the line is covered at all
        if self.coverage_data is None:
            log.critical("The coverage data is not set. Please set the coverage data before using this tool.")
            assert(False)
        
        if file_name not in self.coverage_data:
            return f"None of the line in file {file_name} was covered during the execution of the input."
        
        line_covered = False
        for func in self.coverage_data[file_name].keys():
            if line_number in self.coverage_data[file_name][func]:
                line_covered = True
                break
                
        if not line_covered:
            covered_ranges = []
            for func in self.coverage_data[file_name].keys():
                lines = self.coverage_data[file_name][func]
                covered_ranges += self._list_to_intervals(lines)
            feedback = ''
            feedback += f"The line {line_number} was not hit during the execution of the last input."
            feedback += f"The following lines were hit: {', '.join(covered_ranges)}."
            return feedback
        
        # NOTE: it is now safe to set a breakpoint at the line number!
        succ, _ = self.run_arbitrary_gdb_command(f"break {file_name}:{line_number}")
        if not succ:
            self.stop_debugger()
            return f"Could not retrieve the value of the variable\n. Try something else!"
        
        # Continue the program
        succ, _ = self.run_arbitrary_gdb_command("continue")
        if not succ:
            self.stop_debugger()
            return f"Could not retrieve the value of the variable\n. Try something else!"
        
        # Print the variable
        succ, result = self.run_arbitrary_gdb_command(f"print {var_name}")
        if not succ:
            self.stop_debugger()
            return f"Could not retrieve the value of the variable\n. Try something else!"
        
        # Stop the debugger
        self.stop_debugger()

        log.info(f"Result: {result}")

        return result 


    def _list_to_intervals(self, lst):
        if not lst:
            return []
    
        lst = sorted(lst)
        intervals = []
        start = prev = lst[0]
    
        for num in lst[1:]:
            if num == prev + 1:
                prev = num
            else:
                if start == prev:
                    intervals.append(f"{start}")
                else:
                    intervals.append(f"{start}-{prev}")
                start = prev = num
    
        # Add the last interval
        if start == prev:
            intervals.append(f"{start}")
        else:
            intervals.append(f"{start}-{prev}")
    
        return intervals

    def run_arbitrary_gdb_command(self, command: str) -> Tuple[bool, str]:
        """
        Run an arbitrary gdb command in the current debugging session.
        :param commands: the gdb command to run
        :return the output of the gdb commands
        """
        
        res = self.dyva_debugger.raw(command)

        if command == "continue":
            import time
            max_attempt = 3
            attempt = 0
            while True:
                # We need to check if the program is still running
                # FIXME: dyva_debugger.exited is True/False 
                _check_out = self.dyva_debugger.raw("i r")
                for info in _check_out:
                    if info['type'] == 'result':
                        if info['message'] == 'error':
                            return False, ''
                        elif info['message'] == 'done':
                            return True, ''
                # If we are here, we still don't have the results?
                if attempt == max_attempt:
                    return False, ''
                else:
                    attempt += 1
                    time.sleep(1)
                    continue

        elif command.startswith("print"):

            # Let's get the type
            new_res = self.dyva_debugger.raw(f"whatis {command.split(' ')[1]}")

            for l in new_res:
                if l['type'] == 'console':
                    _var_type = l['payload'].split('=')[1].strip()

            _feedback = f'The variabile is of type `{_var_type}` and its value is `'
            for l in res:
                if l['type'] == 'console':
                    _val = l['payload'].split('=')[1].strip()
                    _feedback += _val + '`\n'
                    return True, _feedback
            return False, ""
        
        elif command.startswith("break"):
            return True, ""

        else:
            print(f"Unknown command: {command}")
            pass

        return res

    def stop_debugger(self) -> str:
        self.dyva_debugger.quit()
