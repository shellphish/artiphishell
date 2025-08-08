# Standard library imports
import os
import re
import yaml
import time
import logging
import argparse
import traceback
from pathlib import Path
from typing import Dict, Optional

# Local imports
from grammaroomba.globals import GLOBALS
from grammaroomba.agents.toolcalls import find_function, set_target_function, get_files_in_directory, get_functions_in_file, remember, check_grammar_coverage, resolve_function_name, grep_sources, get_file_content
from grammaroomba.grammars import NautilusPythonGrammar

# Shellphish imports 
from agentlib.lib.common import LLMApiBudgetExceededError
from agentlib import Agent, tools, AgentWithHistory, AgentResponse, tools
#
from coveragelib.trace import Tracer
from coveragelib.parsers import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco
#
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.symbols import SourceLocation
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation

log = logging.getLogger("grammaroomba.GrammarMutator")

class GrammarMutator(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'GrammarMutator.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'GrammarMutator.user.j2'
    __LLM_MODEL__ = 'gpt-o4-mini'
    __HAS_MEMORY__ = True
    __LLM_ARGS__ = {'max_tokens': 16384}
    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__ = dict( name='remove_turns', number_to_remove="80%" )
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 1

    def __init__(self, *args, crash_report_to_repro: Optional[Path] = None, sanitizer_description: Optional[Path] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__CRASH_REPORT_TO_REPRO__ = crash_report_to_repro
        self.__SANITIZER_DESCRIPTION__ = sanitizer_description

    def on_too_many_tool_validation_errors(self, resp: AgentResponse, name: str, tool_metadata: Dict, all_tool_metadata: Dict):
        self.warn(f"Tool call {name} had many validation errors and ended tool chain early ({tool_metadata.get('num_invalid_tool_calls')} failed validation attempts)")
        while resp.chat_messages and resp.chat_messages[-1].type == "tool" and "<function_call_error>" in resp.chat_messages[-1].content:
            tool_call_id = resp.chat_messages[-1].tool_call_id
            resp.chat_messages.pop()
            # keep popping until we find the corresponding "ai" message
            while resp.chat_messages and not (resp.chat_messages[-1].type == "ai" and any(c["id"] == tool_call_id for c in resp.chat_messages[-1].tool_calls)):
                resp.chat_messages.pop()
            # then pop the "ai" message too
            if resp.chat_messages:
                resp.chat_messages.pop()

    def run(self, function_meta, **kwargs):

        MAX_ROUNDS_WITHOUT_PROGRESS = 5
        num_rounds_without_progress = 0
        # Make use of function meta information
        previously_covered_lines = 0
        while True:
            try:
                covered_lines = 0
                input_dict = dict(
                    nautilus_grammar=function_meta.grammar,
                    function_source=function_meta.source_code,
                    harness_source=GLOBALS.harness_source_code,
                    target_function_name=function_meta.function_index_key,
                )
                response = self.invoke(input_dict)
                covered_lines, coverage_status = self.parse_covered_lines_and_grammar_from_response(response.value)
                if covered_lines == -1:
                    log.error("Failed to parse covered lines from response.")
                    continue
                if "fully covered" in coverage_status.lower():
                    log.info(f"Function {function_meta.function_index_key} was fully covered! DAMN! Covered lines: {covered_lines}/{function_meta.total_lines}\n" +
                            "################################################################################################################")
                    return True, "fc"
                if "coverage maximized" in coverage_status.lower():
                    log.info(f"Function {function_meta.function_index_key} was improved. No further improvement feasible. Covered lines: {covered_lines}/{function_meta.total_lines}\n" +
                            "################################################################################################################")
                    return True, ''
                if'not improvable' in coverage_status.lower():
                    log.info(f"Function can not be improved further. Covered lines: {covered_lines}/{function_meta.total_lines}\n" +
                            "################################################################################################################")
                    return False, ''
                
                if previously_covered_lines <= covered_lines:
                    num_rounds_without_progress += 1
                    log.warning(f"Rounds without progress: {num_rounds_without_progress}/{MAX_ROUNDS_WITHOUT_PROGRESS}")
                    if num_rounds_without_progress >= MAX_ROUNDS_WITHOUT_PROGRESS:
                        log.warning("No progress made in the last 5 rounds. Clearing the chat history.")
                        self.chat_history.clear()
                        num_rounds_without_progress = 0
                        return False, ''
                else:
                    log.info(f"🥳🥳 Improved coverage from {previously_covered_lines} to {covered_lines} lines. 🥳🥳")
                    num_rounds_without_progress = 0
                    previously_covered_lines = covered_lines
                    return True, ''

            except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded. Waiting for 1 minute before retrying.")
                time.sleep(60)
            except Exception as e:
                print(f"An error occurred: {e}")
                log.error(f"An error occurred: {e}", exc_info=True)
                self.chat_history.clear()
                num_rounds_without_progress = 0
    
    def parse_covered_lines_and_grammar_from_response(self, response: str):
        '''
        Extracts the number of covered lines and coverage status from a response string.
        '''
        # Match <hit_lines>...</hit_lines>
        lines_pattern = re.compile(r"<hit_lines>\s*(\d+)\s*</hit_lines>", re.DOTALL)
        lines_match = re.search(lines_pattern, response)
        covered_lines = int(lines_match.group(1)) if lines_match else -1

        # Match <coverage_status>...</coverage_status> with DOTALL for multiline
        status_pattern = re.compile(r"<coverage_status>\s*(.*?)\s*</coverage_status>", re.DOTALL)
        status_match = re.search(status_pattern, response)
        coverage_status = status_match.group(1) if status_match else "Not provided"

        return covered_lines, coverage_status

    def get_available_tools(self):
        tools = [
            remember,
            grep_sources,
            find_function,
            get_file_content,
            get_functions_in_file,
            check_grammar_coverage,
            get_files_in_directory,
        ]
        # print(f"Getting available tools for GrammarMutator {tools}")
        return tools