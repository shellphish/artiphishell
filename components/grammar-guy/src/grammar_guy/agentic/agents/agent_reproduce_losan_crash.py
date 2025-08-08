
import argparse
import logging
import os
import time
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import traceback
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.models.crs_reports import RepresentativeFullPoVReport
from shellphish_crs_utils.models.crash_reports import LosanSanitizerEnum
from shellphish_crs_utils.utils import safe_decode_string
import yaml
from typing import Dict, List, Optional, Tuple, TypeAlias, Union

import agentlib
from agentlib.lib.common import LLMApiBudgetExceededError
from agentlib import AgentWithHistory, tools
from agentlib import enable_event_dumping
from agentlib import Agent
from agentlib import tools

from coveragelib.trace import Tracer
from coveragelib.parsers import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco

from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation import LosanInstrumentation
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.crash_reports import LosanSanitizerEnum

from grammar_guy.agentic.agents.gg_tools import find_function, get_functions_in_file, remember, check_grammar_coverage, resolve_function_name
from grammar_guy.agentic.grammars import NautilusPythonGrammar
from grammar_guy.agentic.run_agent import run_agent
from grammar_guy.agentic.sanitizer_descriptions import LosanSanitizerEnum
from grammar_guy.agentic.globals import get_coverage_tracer, get_function_resolver, GRAMMAR_FUNCTION_COVERAGES, MEMORIES, register_grammar_coverage, set_coverage_target, set_coverage_tracer, set_function_resolver, set_losan_target

TARGET_FUNCTION_KEY = None
CRASHING_INPUT_PATH = None

log = logging.getLogger("grammar_guy")

@tools.tool
def eval_python_expr_on_crashing_input(script: str):
    '''
    You can use this to run a python script on the given crashing input to decode encoded information.
    The path to the crashing input will be passed to the script as the contents of `stdin` and should
    be accessed via `sys.stdin.buffer` to support arbitrary byte sequences.
    You should be sure to include helpful printing and meaningful messages that illustrate incremental progress in case of failure.
    You should split out the logic into separate functions and use `try`/`except` blocks to catch exceptions and print helpful error messages.
    You should also comment each step with the intended purpose of the code.

    You will **ONLY** receive STDOUT and STDERR from the script. You should print out any decoded information to STDOUT. You must not write any
    data to disk or perform any other side effects.

    An example script that decodes packed struct fields that were first zlib compressed and then base64 encoded:

    ```python
    import sys
    import base64
    import zlib
    import struct
    
    data = sys.argv[1]
    with open(data, 'r') as f:
        data = f.read()
    print(f"Read data: {data!r}")

    # base64 decode the data
    try:
        decoded = base64.b64decode(data)
        print(f"Decoded data: {decoded!r}")
    except Exception as e:
        print(f"Failed to decode data: {e}")
        raise e

    # decompress the data with zlib
    try:
        decompressed = zlib.decompress(decoded)
        print(f"Decompressed data: {decompressed!r}")
    except Exception as e:
        print(f"Failed to decompress data: {e}")
        raise e

    # unpack the struct fields
    try:
        unpacked = struct.unpack('<IIHH', decompressed)
        print(f"Unpacked data: {unpacked}")
    except Exception as e:
        print(f"Failed to unpack data: {e}")
        raise e
    ```
    '''

    with tempfile.TemporaryDirectory() as tmpdir:
        # copy the crashing input to the temp dir
        shutil.copy(CRASHING_INPUT_PATH, tmpdir)
        # write out the script to a file
        script_path = os.path.join(tmpdir, 'script.py')
        with open(script_path, 'w') as f:
            f.write(script)
        # run the script
        proc = subprocess.Popen(['python', script_path, CRASHING_INPUT_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = proc.communicate(timeout=10)
            stdout_stderr_serialized = f"## RETURN CODE\n{proc.returncode}\n## STDOUT\n```\n{stdout}\n```\n## STDERR\n```\n{stderr}\n```"
            if proc.returncode != 0:
                raise ValueError(f"# ERROR\n  Failed to run script on crashing input: \n## STDERR ```\n{stderr}\n```")
            log.info(f"Ran script on crashing input: {stdout_stderr_serialized}")
        except Exception as e:
            log.info(f"Failed to run LLM script on crashing input: {e}", exc_info=True)
            raise ValueError(f"Failed to run script on crashing input: {e}")

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
class CrashReproducerAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'system.generic_reacher.j2'
    __USER_PROMPT_TEMPLATE__ = 'user.follow_crash_report.j2'
    __LLM_MODEL__ = 'claude-4-sonnet'
    __HAS_MEMORY__ = True
    __LLM_ARGS__   = {'max_tokens': 16384}


    def __init__(self, *args, crash_report_to_repro: Optional[Path] = None, sanitizer_description: Optional[Path] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__CRASH_REPORT_TO_REPRO__ = crash_report_to_repro
        self.__SANITIZER_DESCRIPTION__ = sanitizer_description

        self.function_to_reaching_grammar = {}

    # CLI run interface
    def add_args(self, parser: argparse.ArgumentParser):
        parser.add_argument('--representative-crashing-metadata-id', type=str, required=False, help='[Pipeline/Backup Run] ID of the representative crashing metadata')
        parser.add_argument('--representative-crashing-metadata', type=Path, required=False, help='[Pipeline/Backup Run] Path to the representative crashing metadata')
        
        parser.add_argument('--losan-target', type=Path, required=False, help='Path to the losan target folder')

        parser.add_argument('--sanitizer', type=LosanSanitizerEnum, required=False)
        parser.add_argument('--crash-report', type=Path, required=False, help='[Local Run] Path to the crash report to reproduce')
        parser.add_argument('--losan-metadata', type=Path, required=False, help='[Local Run] Path to the losan metadata yaml')
        parser.add_argument('--functions-index', type=Path, required=False, help='[Local Run] Path to the functions index json')
        parser.add_argument('--functions-jsons', type=Path, required=False, help='[Local Run] Path to the functions jsons directory')
        parser.add_argument('--target-function', type=str, nargs='+', required=False, help='[Local Run] Target function to reach')

        parser.add_argument('--output-run-pov-result', type=Path)
        parser.add_argument('--harness-info-id', type=str, required=True)
        parser.add_argument('--harness-info', type=Path, required=True)


    def setup_function_resolver(self, args: argparse.Namespace):
        if args.functions_index and args.functions_jsons:
            function_resolver = LocalFunctionResolver(
                functions_index=args.functions_index,
                functions_jsons=args.functions_jsons,
            )
        else:
            assert self.representative_crash_meta, "You must provide a representative crashing metadata"
            function_resolver = RemoteFunctionResolver(
                cp_name = self.representative_crash_meta.project_name,
                project_id = self.representative_crash_meta.project_id,
            )

        set_function_resolver(function_resolver)

    def setup(self, args: argparse.Namespace):
        assert (args.functions_index and args.functions_jsons) or args.representative_crashing_metadata, "You must provide a functions index and functions jsons"
        
        self.representative_crash_meta = None
        self.representative_crash_meta_path = None
        self.losan_metadata = None
        self.sanitizer = None
        self.target_functions = None
        self.crash_report = None

        self.losan_target = InstrumentedOssFuzzProject(LosanInstrumentation(), args.losan_target)
        self.losan_target.build_runner_image()
        set_losan_target(self.losan_target)

        if args.representative_crashing_metadata:
            self.representative_crash_meta_path = args.representative_crashing_metadata
            with open(args.representative_crashing_metadata) as f:
                representative_crash_meta = RepresentativeFullPoVReport.model_validate(yaml.safe_load(f.read()))
                self.representative_crash_meta = representative_crash_meta

            assert self.representative_crash_meta.run_pov_result.pov.crash_report.losan and self.representative_crash_meta.run_pov_result.pov.crash_report.losan_metadata, "You must provide a losan crash report and metadata"
            self.losan_metadata = self.representative_crash_meta.run_pov_result.pov.crash_report.losan_metadata
            
            self.sanitizer: LosanSanitizerEnum = self.losan_metadata.sanitizer_type

            self.crash_report = safe_decode_string(self.representative_crash_meta.run_pov_result.pov.crash_report.raw_report)
            if args.crash_report:
                with open(args.crash_report) as f:
                    self.crash_report = f.read()
            else:
                self.crash_report = safe_decode_string(self.representative_crash_meta.run_pov_result.pov.crash_report.raw_report)

            self.target_functions = []

            function_resolver = get_function_resolver()
            for _, stack_trace in self.representative_crash_meta.run_pov_result.pov.crash_report.stack_traces.items():
                for ct in stack_trace.call_locations:
                    if not ct.source_location:
                        continue
                    if ct.source_location.function_index_key:
                        self.target_functions.append(ct.source_location.function_index_key)
                        continue
                    
                    if (result := function_resolver.resolve_source_location(ct.source_location)):
                        key, rankings = result[0]
                        print(f"Resolved function {ct.source_location.function_name} to {key} with rankings {rankings}")
                        self.target_functions.append(key)

        else:
            assert args.target_function, "You must provide at least one target function"
            assert args.crash_report, "You must provide a crash report"
            assert args.sanitizer, "You must provide a sanitizer"
            self.target_functions = [resolve_function_name(f) for f in args.target_function]
            with open(args.crash_report) as f:
                self.crash_report = f.read()
            self.sanitizer = args.sanitizer

    def run(self, **kwargs):
        example_grammars = NautilusPythonGrammar.get_example_grammars()
        # make sure nautilus can actually produce inputs
        assert len(list(NautilusPythonGrammar(example_grammars[0]).produce_input(10, unique=True))) >= 10
        
        for i in range(3):
            unreached_functions = [f for f in self.target_functions if not GRAMMAR_FUNCTION_COVERAGES.get(f, [])]
            if not unreached_functions:
                break
            target_function_name = random.choice(unreached_functions)
            assert get_function_resolver().get_with_default(target_function_name, None), f"Could not find function {target_function_name} in the function resolver."
            print(f"Function {target_function_name} has not been reached yet. Trying to write a grammar to reach it.")
            
            _, _, _, target_function_code = get_function_resolver().get_code(target_function_name)
            crash_to_repro = {
                'report': self.crash_report,
                'sanitizer_info': self.sanitizer
            }
            try:
                res = self.invoke(dict(
                    **kwargs,
                    target_name=target_function_name,
                    target=target_function_code,
                    example_grammars=example_grammars,
                    enumerate=enumerate,
                    crash_to_repro=crash_to_repro,
                    memories=MEMORIES,
                ))
                print(res.value)
            except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded. Losan agent is exiting.")
                return
            except Exception as e:
                print(f"An error occurred: {e}")
                log.error(f"An error occurred: {e}", exc_info=True)

    def get_available_tools(self):
        return [
            tools.give_up_on_task,
            find_function,
            check_grammar_coverage,
            get_functions_in_file,
            remember,
            # submit_grammar,
        ]

def main():
    agent = CrashReproducerAgent()
    run_agent(agent)

if __name__ == '__main__':
    main()
