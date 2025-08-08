
import argparse
import json
import logging
import os
import petname
from pathlib import Path
import random
import sys
import tempfile
import time
import traceback
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
import yaml
from typing import Dict, List, Optional, Tuple, TypeAlias, Union

import agentlib
from agentlib.lib.common import LLMApiBudgetExceededError
from agentlib import AgentWithHistory, AgentResponse, tools
from agentlib import enable_event_dumping
from agentlib import Agent
from agentlib import tools

from coveragelib.trace import Tracer
from coveragelib.parsers import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco

from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.symbols import SourceLocation
from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel

from grammar_guy.agentic.agents.gg_tools import find_function, generate_inputs, get_files_in_directory, get_functions_in_file, remember, check_grammar_coverage, resolve_function_name, grep_sources, get_file_content
from grammar_guy.agentic.grammars import NautilusPythonGrammar
from grammar_guy.agentic.run_agent import run_agent_explore
from grammar_guy.agentic.globals import REACHING_FUNCTION_GRAMMARS, set_harness_info_id, set_harness_info, get_coverage_tracer, get_function_resolver, GRAMMAR_FUNCTION_COVERAGES, MEMORIES, register_grammar_coverage, set_coverage_target, set_coverage_tracer, set_function_resolver
from grammar_guy.agentic.codeql_utils import get_indirect_call_targets_within_reach



TARGET_FUNCTION_KEY = None

TARGET_FUNCTION_LIST = []
GIVEN_UP_FUNCTIONS = {}

init_otel("grammar-guy-agentic-explorer", "input-generation", "llm_grammar_generation")
init_llm_otel()
tracer = get_otel_tracer()

log = logging.getLogger("grammar_guy")

MODEL = {
    0: 'claude-4-sonnet',
    1: 'claude-4-sonnet',
    2: 'o3',
    3: 'claude-3.5-sonnet',
}[int(os.getenv("REPLICA_ID", "0"))]
BUDGET = 'grammar-openai-budget'
MAX_TOKENS = 16384 if MODEL == 'claude-3.5-sonnet' else 8192

@tools.tool
def add_goal_function(function_name: str):
    '''
    Add a function to the list of goal functions that the agent should try to reach.
    '''
    global TARGET_FUNCTION_LIST
    resolved_name = resolve_function_name(function_name)

    error_message = ''
    if resolved_name in REACHING_FUNCTION_GRAMMARS:
        error_message += f"Function {resolved_name} was hit and is already in the list of goal functions. Move on to a different goal function."
    elif resolved_name in TARGET_FUNCTION_LIST:
        error_message += f"Function {resolved_name} was never hit but already in the list of goal functions. You cannot add it again."
    else:
        TARGET_FUNCTION_LIST.append(resolved_name)
        return f"Added function {resolved_name} to the list of target functions."


    # Okay, we were unable to add the function due to the above conditions.

    # # First, let's see if there's any indirect call target functions that we can try to reach
    # def filter_func(ref_ident, reached, not_reached):
    #     if not reached: # no reached functions at all => ignore
    #         return False
    #     # check if all not_reached are already in the list of goal functions or given up
    #     if all(f in TARGET_FUNCTION_LIST or f in GIVEN_UP_FUNCTIONS for f in not_reached):
    #         return False

    #     return True

    # indirect_call_table = get_indirect_call_targets_within_reach(filter_func=filter_func)
    # if indirect_call_table:
    #     # pick one set of indirect call targets and add it to the goal functions
    #     ref_ident, (reached, not_reached) = random.choice(list(indirect_call_table.items()))
    #     assert reached and not_reached
    #     not_reached_not_in_goal = [f for f in not_reached if f not in TARGET_FUNCTION_LIST and f not in GIVEN_UP_FUNCTIONS]
    #     assert not_reached_not_in_goal

    #     TARGET_FUNCTION_LIST.extend(not_reached_not_in_goal)
    #     response = f"{error_message}\n"
    #     response += '\n[USER] However, a user has marked the following functions as goal functions: \n\n'
    #     response += '\n'.join(['- ' + repr(f) for f in not_reached_not_in_goal])
    #     response += '\n\n'
    #     response += f"[USER] These functions were identified since they are referenced in `{ref_ident}` and were not reached yet while the functions {reached} were already reached.\n"
    #     return response

    return error_message
    # # Instead, add an unhit function in a file that was already hit
    # function_resolver = get_function_resolver()
    # if resolved_name in REACHING_FUNCTION_GRAMMARS and random.random() < 0.5:
    #     random_hit_function = resolved_name
    # else:
    #     random_hit_function = random.choice([f for f in REACHING_FUNCTION_GRAMMARS if REACHING_FUNCTION_GRAMMARS[f]])
    # file_path = function_resolver.get(random_hit_function).target_container_path
    # other_functions = list(function_resolver.find_by_filename(file_path))
    # unhit_functions = [
    #     f for f in other_functions if
    #     f != random_hit_function and f not in REACHING_FUNCTION_GRAMMARS and f not in TARGET_FUNCTION_LIST
    # ]
    # if not unhit_functions:
    #     return error_message

    # # choice = random.choice(unhit_functions)
    # # TARGET_FUNCTION_LIST.append(choice)
    # # response = f"{error_message}\n[USER] However, a user has additionally marked function {choice} as a goal function. This has been added to the list of goal functions.\n"
    # unhit_functions = random.sample(unhit_functions, min(3, len(unhit_functions)))
    # TARGET_FUNCTION_LIST.extend(unhit_functions)
    # response = f"{error_message}\n[USER] However, a user has additionally marked functions {repr(unhit_functions)} as goal functions. These have been added to the list of goal functions.\n"
    # return response

@tools.tool
def give_up_on_goal(function_name: str, reason: str):
    '''
    Declare that you believe a given goal function is unreachable. ONLY Use this in cases where you believe that the harness and/or general
    program logic makes reaching the target function impossible. Remember that you are NEVER allowed to modify the harness. If you are absolutely
    certain that reaching a given goal function would require harness changes, use this function to give up on it.

    Args:
        function_name: The name of the function you are giving up on reaching.
        reason: A brief explanation of why you believe the function is unreachable. Should include a description of the harness logic that
                makes reaching the function impossible.
    '''
    global GIVEN_UP_FUNCTIONS
    resolved_name = resolve_function_name(function_name)
    if resolved_name not in TARGET_FUNCTION_LIST:
        return f"Function {resolved_name} is not a goal function."
    if resolved_name not in GIVEN_UP_FUNCTIONS:
        GIVEN_UP_FUNCTIONS[resolved_name] = reason
    else:
        return f"Function {resolved_name} has already been given up on. The previously given reason was {GIVEN_UP_FUNCTIONS[resolved_name]!r}. Move on to a different goal function."
    return f"Given up on function {resolved_name} because {reason!r}. You must attempt to now reach a different goal function or discover new goal functions."

def get_goal_report():
    goal_report = "# GOAL REPORT: Successfully hit functions\n"
    goal_report += " SUCCESS | FUNCTION | Reason why we gave up (if given, do not pursue this goal function)\n"
    for target_function_name in TARGET_FUNCTION_LIST:
        covered = target_function_name in REACHING_FUNCTION_GRAMMARS

        goal_report += f"{'✅' if covered else '❌'} | {target_function_name} | {GIVEN_UP_FUNCTIONS.get(target_function_name, 'N/A')}\n"

    goal_report += "\n\n"
    return goal_report

@tools.tool
def goal_report():
    '''
    Returns a report of the current goal functions and their status.
    '''
    return get_goal_report()

# Agent takes a dict of input vars to template and returns a string
class ExplorerAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'system.explorer.j2'
    __USER_PROMPT_TEMPLATE__ = 'user.explorer.j2'
    __LLM_MODEL__ = MODEL
    __HAS_MEMORY__ = True
    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__ = dict( name='remove_turns', number_to_remove="80%" )
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 1
    __LLM_ARGS__                = {'max_tokens': MAX_TOKENS}

    def __init__(self, *args, crash_report_to_repro: Optional[Path] = None, sanitizer_description: Optional[Path] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__CRASH_REPORT_TO_REPRO__ = crash_report_to_repro
        self.__SANITIZER_DESCRIPTION__ = sanitizer_description

    # CLI run interface
    def add_args(self, parser: argparse.ArgumentParser):
        # parser.add_argument('--harness-info-id', type=str, required=True)
        # parser.add_argument('--harness-info', type=Path, required=True)
        parser.add_argument('--commit-functions-index', type=Path, required=False)
        parser.add_argument('--commit-functions-jsons-dir', type=Path, required=False)
        pass

    def setup(self, args: argparse.Namespace):
        # set_harness_info_id(args.harness_info_id)
        # set_harness_info(HarnessInfo.model_validate(yaml.safe_load(args.harness_info.read_text())))
        if args.commit_functions_index:
            # load the functions index

            commit_function_resolver = LocalFunctionResolver(args.commit_functions_index, args.commit_functions_jsons_dir)
            full_function_resolver = get_function_resolver()

            for function_key in commit_function_resolver.keys():
                function_entry = commit_function_resolver.get(function_key)
                full_function_keys_to_hit = set()
                if full_function_resolver.get_with_default(function_key, default=None) is not None:
                    full_function_keys_to_hit.add(function_key)
                else:
                    resolved_full_locations_rankings = list(full_function_resolver.resolve_source_location(
                        SourceLocation.create(
                            full_file_path=function_entry.target_container_path,
                            focus_repo_relative_path=function_entry.focus_repo_relative_path,
                            line_number=function_entry.start_line,
                            function_name=function_entry.funcname,
                        )
                    ))
                    mapped_entries, missing = full_function_resolver.find_matching_indices(
                        [x[0] for x in resolved_full_locations_rankings],
                        scope='compiled',
                        can_include_self=True,
                    )
                    full_function_keys_to_hit.update(mapped_entries.values())

                for function_key in full_function_keys_to_hit:
                    try:
                        add_goal_function.get_tool().invoke(function_key)
                    except:
                        log.warning("Could not add function {function_key} to goal functions???", exc_info=True)
                        if artiphishell_should_fail_on_error():
                            raise

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

    def run(self, **kwargs):
        example_grammars = NautilusPythonGrammar.get_example_grammars()
        # make sure nautilus can actually produce inputs
        assert len(list(NautilusPythonGrammar(example_grammars[0]).produce_input(10, unique=True))) >= 10

        global REACHING_FUNCTION_GRAMMARS
        global TARGET_FUNCTION_LIST

        MAX_ROUNDS_WITHOUT_PROGRESS = 5
        num_rounds_without_progress = 0
        while True:
            try:
                num_reaching_functions_before = len(REACHING_FUNCTION_GRAMMARS)
                num_target_functions_before = len(TARGET_FUNCTION_LIST)

                res = self.invoke(dict(
                    **kwargs,
                    example_grammars=example_grammars,
                    enumerate=enumerate,
                    goal_report=get_goal_report(),
                    memories=MEMORIES,
                ))
                print(res.value)

                if len(REACHING_FUNCTION_GRAMMARS) <= num_reaching_functions_before and len(TARGET_FUNCTION_LIST) <= num_target_functions_before:
                    num_rounds_without_progress += 1
                    log.warning(f"Rounds without progress: {num_rounds_without_progress}/{MAX_ROUNDS_WITHOUT_PROGRESS}")
                    if num_rounds_without_progress >= MAX_ROUNDS_WITHOUT_PROGRESS:
                        log.warning("No progress made in the last 5 rounds. Clearing the chat history.")
                        self.chat_history.clear()
                        num_rounds_without_progress = 0
                else:
                    num_rounds_without_progress = 0
            except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded. Waiting for 1 minute before retrying.")
                time.sleep(60)
            except Exception as e:
                print(f"An error occurred: {e}")
                log.error(f"An error occurred: {e}", exc_info=True)
                self.chat_history.clear()
                num_rounds_without_progress = 0

    def get_available_tools(self):
        return [
            tools.give_up_on_task,
            add_goal_function,
            give_up_on_goal,
            goal_report,
            find_function,
            # generate_inputs,
            check_grammar_coverage,
            remember,
            grep_sources,
            get_file_content,
            get_functions_in_file,
            get_files_in_directory,
        ]

def main():
    agent = ExplorerAgent()
    # run_agent_explore is adjusted. run_agent is the same (for losan reproducer)
    run_agent_explore(agent)

if __name__ == '__main__':
    with tracer.start_as_current_span("grammar_guy.agentic.agents.agent_explorer") as span:
        main()
        span.set_status(status_ok())
