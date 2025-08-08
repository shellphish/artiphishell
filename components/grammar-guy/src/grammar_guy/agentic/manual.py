
import argparse
import os
from pathlib import Path
import sys
import tempfile
import traceback
from agentlib import enable_event_dumping
from coveragelib.trace import Tracer
from agentlib import Agent

from typing import Dict, List, Optional, Tuple, TypeAlias, Union

from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, FunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap

from coveragelib.parsers import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco
import yaml


import agentlib
from agentlib import AgentWithHistory, tools

from grammar_guy.cli.nautilus_grammar import NautilusPythonGrammar


COVERAGE_TARGET: InstrumentedOssFuzzProject = None
COVERAGE_TRACER: Tracer = None
FUNCTION_RESOLVER: FunctionResolver = None


# We can make a quick tool by using the @tool.tool decorator
# Make sure to add type hints which are provided to the LLM
# You must also include a docstring which will be used as the tool description
def resolve_function_name(name) -> str:
    func = list(FUNCTION_RESOLVER.find_by_funcname(name))
    if len(func) > 1:
        raise ValueError(f"Found multiple functions with name {name}. Please be more specific. Options are: {func}")
    elif len(func) == 1:
        return func[0]
        
    func = list(FUNCTION_RESOLVER._find_matching_indices(name))
    if len(func) > 1:
        raise ValueError(f"Found multiple functions that could match {name}. Please be more specific. Options are: {func}")
    elif len(func) == 1:
        return func[0]
    raise ValueError(f"Could not find any function matching {name}.")

@tools.tool
def find_function(name: str) -> Tuple[str, str]:
    """
    Return information about the function named `name`. Includes metadata as well as the source code if found.
    """
    global FUNCTION_RESOLVER
    
        
    key = resolve_function_name(name)
    entry = FUNCTION_RESOLVER.get(key)
    return f'''
# {entry.target_container_path}:{entry.start_line}
<code>
{entry.code}
</code>
'''

@tools.tool
def generate_inputs(grammar: str) -> List[bytes]:
    '''
    Generates 10 example inputs from a given grammar. This should be called after a grammar is generated to ensure the outputs match the expected format and to avoid formatting issues.
    '''

    
    if error := NautilusPythonGrammar.check_grammar(grammar):
        raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")
    
    g = NautilusPythonGrammar(grammar)
    try:
        return repr(list(g.produce_input(10, unique=True)))
    except Exception as e:
        import traceback; traceback.print_exc()
        
        raise ValueError(f"ERROR: Failed to generate 10 inputs from grammar: {e}")
    
@tools.tool
def get_grammar_function_coverage(grammar: str, functions_to_check: List[str]) -> Dict[str, List[int]]:
    '''
    Returns the a line coverage report of the coverage reached by `grammar` in the functions `functions_to_check`. This can be used to evaluate the
    coverage of a grammar in any given function in the target application to discover which parts of the code are not being reached.
    '''
    if error := NautilusPythonGrammar.check_grammar(grammar):
        raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")
    
    
    keys_of_interest = [resolve_function_name(name) for name in functions_to_check]
    g = NautilusPythonGrammar(grammar)
    try:
        with tempfile.TemporaryDirectory() as output_dir:
            inputs = list(g.produce_input_files(100, output_dir=Path(output_dir), unique=True))
            file_coverage: FileCoverageMap = COVERAGE_TRACER.trace(*inputs)

        function_coverage: FunctionCoverageMap = FUNCTION_RESOLVER.get_function_coverage(file_coverage, function_keys_of_interest=keys_of_interest)
        reports = []
        for key in keys_of_interest:
            focus_repo_rel_path, target_container_path, func_start_line, func_code = FUNCTION_RESOLVER.get_code(key)

            func_cov_lines = list(sorted(function_coverage[key], key=lambda x: x.line_number))

            report = f'# Coverage Report ({len(inputs)} unique inputs)\n'
            report += f'## {key}\n'
            report += f'## {target_container_path}:{func_start_line}\n'
            report = f'Line | {"Count":8} | Code\n'
            for i, line in enumerate(func_code.split('\n')):
                count = None
                if func_cov_lines and func_cov_lines[0].line_number == i + func_start_line:
                    cur = func_cov_lines.pop(0)
                    count = cur.count_covered

                report += f'{i+func_start_line:4} | {count if count is not None else "":8} | {line}\n'

            reports.append(report)

        report = '\n\n'.join(reports)

        if len(inputs) < 100:
            report += f'\n\n# WARNING: Only {len(inputs)} inputs were generated. This is likely due to the grammar being too restrictive. Note that a grammar that is not generalized enough will be rejected by the submission.'
        return report

    except Exception as e:
        import traceback; traceback.print_exc()
        
        raise ValueError(f"ERROR: Failed to generate inputs from grammar: {e}")

@tools.tool
def submit_successful_grammar(grammar: str):
    '''
    Submits a grammar to the project repository. The grammar will be validated and checked to ensure that it is valid, generalized enough and hits the target function.
    '''
    if error := NautilusPythonGrammar.check_grammar(grammar):
        raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")
    
    grammar = NautilusPythonGrammar(grammar)
    
    try:
        with tempfile.TemporaryDirectory() as output_dir:
            inputs = list(grammar.produce_input_files(100, output_dir=Path(output_dir), unique=True))
            if len(inputs) < 100:
                raise ValueError(f"ERROR: The grammar is too restrictive. It only generates {len(inputs)} inputs.")
            
            file_coverage: FileCoverageMap = COVERAGE_TRACER.trace(*inputs)
            function_coverage: FunctionCoverageMap = FUNCTION_RESOLVER.get_function_coverage(file_coverage, function_keys_of_interest=[TARGET_FUNCTION_KEY])
            lines_covered = [l for l in function_coverage[TARGET_FUNCTION_KEY] if l.count_covered > 1]

            if all(l.count_covered == 1 for l in lines_covered):
                raise ValueError(f"ERROR: The grammar is not generalized enough. It only generates a single input that hits the target function.")
            if not lines_covered:
                raise ValueError(f"ERROR: The grammar does not hit the target function.")

    except Exception as e:
        import traceback; traceback.print_exc()
        
        raise ValueError(f"ERROR: Failed to validate grammar: {e}")

    print(f"Successfully submitted grammar: {grammar}")
    sys.exit(0)
        
    
MEMORIES = []
@tools.tool
def remember(message: str):
    '''
    Remembers a message for future reference. Your memories must be short and succinct as they are limited to 256 characters each.
    Furthermore, you can only remember up to 10 messages. Make sure to use this tool wisely and to only remember crucial pieces
    of information.
    '''
    global MEMORIES
    if len(MEMORIES) >= 10:
        raise ValueError("You can only remember up to 10 messages.")
    if len(message) > 256:
        raise ValueError("Your memory must be less than 100 characters.")
    MEMORIES.append(message)
    return "Remembered: " + message
    

# Agent takes a dict of input vars to template and returns a string
class GrammarAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'src/grammar_guy/cli/prompts/grammar_agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'src/grammar_guy/cli/prompts/grammar_agent.user.j2'
    __LLM_MODEL__ = 'claude-3-5-sonnet'
    __HAS_MEMORY__ = True
    #__LLM_MODEL__ = 'gpt-4o'

    def get_available_tools(self):
        return [
            # Import some predefined tools
            # tools.run_shell_command,
            tools.give_up_on_task,
            find_function,
            # generate_inputs,
            get_grammar_function_coverage,
            remember,
            submit_successful_grammar,
            # Here is our own tool
            # find_function,
        ]
    
    def trigger_callback_event(self, event_name, *args, config=None, **kwargs):
        return super().trigger_callback_event(event_name, *args, config=config, **kwargs)

TARGET_FUNCTION_KEY: FUNCTION_INDEX_KEY = None
def main():
    global COVERAGE_TRACER
    global FUNCTION_RESOLVER
    global COVERAGE_TARGET
    global TARGET_FUNCTION_KEY

    parser = argparse.ArgumentParser()
    parser.add_argument('--harness-info-id', type=str, required=True)
    parser.add_argument('--coverage-target', type=Path, required=True)
    parser.add_argument('--harness-info', type=Path, required=True)
    parser.add_argument('--full-functions-index', type=Path, required=True)
    parser.add_argument('--full-functions-jsons', type=Path, required=True)
    ARGS = parser.parse_args()

    with open(ARGS.harness_info) as f:
        harness_info = HarnessInfo.model_validate(yaml.safe_load(f.read()))

    COVERAGE_TARGET = InstrumentedOssFuzzProject(
        CoverageFastInstrumentation(),
        ARGS.coverage_target,
        project_id=harness_info.project_id,
    )
    parser = {
        LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
    }[COVERAGE_TARGET.project_metadata.language]()

    COVERAGE_TRACER = Tracer(ARGS.coverage_target, harness_info.cp_harness_name, aggregate=True, parser=parser)
    FUNCTION_RESOLVER = LocalFunctionResolver(ARGS.full_functions_index, ARGS.full_functions_jsons)

    agent = GrammarAgent()

    # Set it up so we can see the agentviz ui for this specific agent instance
    # (run `agentviz` it in this dir)
    agent.use_web_logging_config(clear=True)
    agentlib.enable_event_dumping('./events')

    example_grammars = NautilusPythonGrammar.get_example_grammars()
    NautilusPythonGrammar(example_grammars[0]).produce_input(10, unique=True)

    harness_function_name = 'fuzzerTestOneInput' if COVERAGE_TARGET.project_metadata.language == LanguageEnum.jvm else 'LLVMFuzzerTestOneInput'
    harness_function_key = None
    for key in FUNCTION_RESOLVER._find_matching_indices(harness_function_name):
        if harness_info.cp_harness_name in key:
            harness_function_key = key
            break
    
    harness_index = FUNCTION_RESOLVER.get(harness_function_key)
    harness_path = harness_index.target_container_path
    harness_source_code = harness_index.code
    with COVERAGE_TRACER:
        print("WARNING! This agent will run commands unsandboxed in the CWD, proceed with caution.")

        while True:
            target_function_code = None
            target_function_name = None
            while target_function_code is None:
                target_function_name = input('Function name you would like to reach? ')
                try:
                    key = resolve_function_name(target_function_name)
                    target_function_code = FUNCTION_RESOLVER.get(key).code
                    TARGET_FUNCTION_KEY = key
                except Exception as e:
                    traceback.print_exc()
                    print(e)
                    target_function_code = None
                    target_function_name = None

            res = agent.invoke(dict(
                harness_path=str(harness_path),
                harness=harness_source_code,
                target_name=target_function_name,
                target=target_function_code,
                example_grammars=example_grammars,
                enumerate=enumerate,
                memories=MEMORIES,
            ))
            print(res.value)

if __name__ == '__main__':
    main()