
import argparse
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import traceback
from shellphish_crs_utils.models.crs_reports import RunPoVResult
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
from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap

from grammar_guy.agentic.agents.gg_tools import find_function, remember, check_grammar_coverage, resolve_function_name
from grammar_guy.agentic.grammars import NautilusPythonGrammar
from grammar_guy.agentic.run_agent import run_agent
from grammar_guy.agentic.globals import get_coverage_tracer, get_function_resolver, GRAMMAR_FUNCTION_COVERAGES, MEMORIES, register_grammar_coverage, set_coverage_target, set_coverage_tracer, set_function_resolver

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
            inputs = list(grammar.produce_input_files(100, output_dir=Path(output_dir), unique=True))
            
            file_coverage: FileCoverageMap = get_coverage_tracer().trace(*inputs)
            function_coverage: FunctionCoverageMap = get_function_resolver().get_function_coverage(file_coverage, function_keys_of_interest=[TARGET_FUNCTION_KEY])
            
            register_grammar_coverage(grammar, file_coverage, function_coverage)
            lines_covered = [l for l in function_coverage.get(TARGET_FUNCTION_KEY, []) if l.count_covered and l.count_covered > 1]

            if not lines_covered:
                raise ValueError(f"ERROR: The grammar does not hit the target function.")

    except Exception as e:
        import traceback; traceback.print_exc()
        raise ValueError(f"ERROR: Failed to validate grammar: {e}")

    print(f"Successfully submitted grammar: {grammar}")
    raise tools.ToolSignal()

# Agent takes a dict of input vars to template and returns a string
class SarifConfirmingAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'system.generic_reacher.j2'
    __USER_PROMPT_TEMPLATE__ = 'user.reach_sarif.j2'
    __LLM_MODEL__ = 'claude-3-5-sonnet'
    __HAS_MEMORY__ = True


    def __init__(self, *args, crash_report_to_repro: Optional[Path] = None, sanitizer_description: Optional[Path] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__CRASH_REPORT_TO_REPRO__ = crash_report_to_repro
        self.__SANITIZER_DESCRIPTION__ = sanitizer_description

        self.targeted_functions = []
        self.sarif_report_results = None

    # CLI run interface
    def add_args(self, parser: argparse.ArgumentParser):
        parser.add_argument('--sarif-report', type=Path, help='The SARIF report to confirm')

    def setup(self, args: argparse.Namespace):
        parsed_sarif = json.loads(args.sarif_report.read_text())
        results = parsed_sarif.get('runs', [{}])[0].get('results', [])
        
        self.sarif_report_results = results
        self.targeted_functions = []
        for result in results:
            ruleId = result.get('ruleId')
            ruleMessage = result.get('message', {}).get('text')
            locations = result.get('locations', [])
            for location in locations:
                assert (physicalLocation := location.get('physicalLocation')), f"Could not find physical location in location: {location}"
                assert (artifactLocation := physicalLocation.get('artifactLocation')), f"Could not find artifact location in physical location: {physicalLocation}"
                assert (region := physicalLocation.get('region')), f"Could not find region in physical location: {physicalLocation}"

                line = region['startLine']
                found_funcs = []
                for func_key in get_function_resolver().find_by_filename(artifactLocation['uri']):
                    start, end = get_function_resolver().get_function_boundary(func_key)
                    if start <= line <= end:
                        found_funcs.append(func_key)
                if len(found_funcs) > 1:
                    raise ValueError(f"Found multiple functions for line {line} in file {artifactLocation['uri']}: {found_funcs}")
                elif not found_funcs:
                    print(f"Could not find function for line {line} in file {artifactLocation['uri']}")
                    continue
                for f in found_funcs:
                    if f not in self.targeted_functions:
                        self.targeted_functions.append(f)

    def run(self, **kwargs):
        example_grammars = NautilusPythonGrammar.get_example_grammars()
        # make sure nautilus can actually produce inputs
        assert len(list(NautilusPythonGrammar(example_grammars[0]).produce_input(10, unique=True))) >= 10
        
        while True:
            unreached_functions = [f for f in self.targeted_functions if not GRAMMAR_FUNCTION_COVERAGES.get(f, [])]
            if not unreached_functions:
                break
            target_function_name = random.choice(unreached_functions)
            assert target_function_name in get_function_resolver().functions_index, f"Could not find function {target_function_name} in the function resolver."
            print(f"Function {target_function_name} has not been reached yet. Trying to write a grammar to reach it.")
            
            target_function_code = get_function_resolver().get_code(target_function_name)

            res = self.invoke(dict(
                **kwargs,
                target_name=target_function_name,
                target=target_function_code[3],
                example_grammars=example_grammars,
                enumerate=enumerate,
                sarif_report_results=json.dumps(self.sarif_report_results, indent=2),
                memories=MEMORIES,
            ))
            print(res.value)

    def get_available_tools(self):
        return [
            tools.give_up_on_task,
            # find_function,
            check_grammar_coverage,
            remember,
            # submit_grammar,
        ]

def main():
    agent = SarifConfirmingAgent()
    run_agent(agent)

if __name__ == '__main__':
    main()
