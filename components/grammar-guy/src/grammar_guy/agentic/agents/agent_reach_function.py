
import argparse
import os
from pathlib import Path
import random
import sys
import tempfile
import traceback
import yaml
from typing import Dict, List, Optional, Tuple, TypeAlias, Union

import agentlib
from agentlib import AgentWithHistory, tools
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
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap

from grammar_guy.agentic.agents.gg_tools import find_function, remember, check_grammar_coverage, resolve_function_name, find_functions_in_file
from grammar_guy.agentic.grammars import NautilusPythonGrammar
from grammar_guy.agentic.run_agent import run_agent
from grammar_guy.agentic.globals import GRAMMAR_FUNCTION_COVERAGES, MEMORIES, set_coverage_target, set_coverage_tracer, set_function_resolver, get_coverage_tracer, get_function_resolver, get_coverage_target

TARGET_FUNCTION_KEY = None

@tools.tool
def submit_grammar(grammar: str):
    '''
    Submit a grammar for evaluation. The grammar will be validated and checked to ensure that it is valid, generalized enough and hits the target function.
    '''
    if error := NautilusPythonGrammar.check_grammar(grammar):
        raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")
    
    grammar = NautilusPythonGrammar(grammar)
    try:
        with tempfile.TemporaryDirectory() as output_dir:
            inputs = list(grammar.produce_input_files(20, output_dir=Path(output_dir), unique=True))
            if len(inputs) < 10:
                raise ValueError(f"ERROR: The grammar is too restrictive. It only generates {len(inputs)} inputs. YOU ARE NOT ALLOWED TO SUBMIT THIS GRAMMAR.")
            
            file_coverage: FileCoverageMap = get_coverage_tracer().trace(*inputs)
            function_coverage: FunctionCoverageMap = get_function_resolver().get_function_coverage(file_coverage, function_keys_of_interest=[TARGET_FUNCTION_KEY])

            lines_covered = [l for l in function_coverage.get(TARGET_FUNCTION_KEY, []) if l.count_covered and l.count_covered > 1]

            if not lines_covered:
                raise ValueError(f"ERROR: The grammar does not hit the target function.")

    except Exception as e:
        import traceback; traceback.print_exc()
        raise ValueError(f"ERROR: Failed to validate grammar: {e}")

    print(f"Successfully submitted grammar: {grammar.grammar}")
    raise tools.ToolSignal()

# Agent takes a dict of input vars to template and returns a string
class FunctionReacherAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'system.generic_reacher.j2'
    __USER_PROMPT_TEMPLATE__ = 'user.reach_function.j2'
    __LLM_MODEL__ = 'claude-3-5-sonnet'
    __HAS_MEMORY__ = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_available_tools(self):
        return [
            tools.give_up_on_task,
            find_function,
            check_grammar_coverage,
            remember,
            find_functions_in_file,
        ]
    
    # CLI run interface
    def add_args(self, parser: argparse.ArgumentParser):
        parser.add_argument('--target-function', type=str, help='The target function to reach, can be provided multiple times', action='append')
        parser.add_argument('--harness-info-id', type=str, required=True)
        parser.add_argument('--harness-info', type=Path, required=True)

    def setup(self, args: argparse.Namespace):
        if args.target_function:
            self.target_functions = [resolve_function_name(f) for f in args.target_function]
            return
        self.target_functions = []
        while True:
            target_function = input("Enter the target function to reach: ")
            if not target_function:
                break
            func_key = resolve_function_name(target_function)
            if not func_key:
                print(f"Could not find function {target_function}.")
                continue
            self.target_functions.append(func_key)

    def run(self, **kwargs):
        example_grammars = NautilusPythonGrammar.get_example_grammars()
        # make sure nautilus can actually produce inputs
        assert len(list(NautilusPythonGrammar(example_grammars[0]).produce_input(10, unique=True))) >= 10
        
        while True:
            unreached_functions = [f for f in self.target_functions if not GRAMMAR_FUNCTION_COVERAGES.get(f, [])]
            if not unreached_functions:
                break
            target_function_name = random.choice(unreached_functions)
            assert target_function_name in get_function_resolver().functions_index, f"Could not find function {target_function_name} in the function resolver."
            print(f"Function {target_function_name} has not been reached yet. Trying to write a grammar to reach it.")
            
            _, _, _, target_function_code = get_function_resolver().get_code(target_function_name)

            res = self.invoke(dict(
                **kwargs,
                target_name=target_function_name,
                target=target_function_code,
                example_grammars=example_grammars,
                enumerate=enumerate,
                memories=MEMORIES,
            ))
            print(res.value)

def main():
    agent = FunctionReacherAgent()
    run_agent(agent)

if __name__ == '__main__':
    main()
