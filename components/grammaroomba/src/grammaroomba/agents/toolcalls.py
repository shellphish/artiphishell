# Standard library imports
import os
import yaml
import shlex
import logging
import tempfile
import traceback
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from agentlib import tools
from coveragelib.trace import Tracer
from shellphish_crs_utils.utils import safe_decode_string
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY
from shellphish_crs_utils.utils import safe_decode_string

from grammaroomba.grammars import NautilusPythonGrammar
from grammaroomba.globals import register_grammar_coverage, save_new_crashing_inputs, save_new_fuzzer_inputs, GLOBALS

log = logging.getLogger("grammaroomba.toolcalls")
# We can make a quick tool by using the @tool.tool decorator
# Make sure to add type hints which are provided to the LLM
# You must also include a docstring which will be used as the tool description
def resolve_function_name(name) -> str:
    funcs = list(GLOBALS.function_resolver.resolve_with_leniency(name))
    if len(funcs) > 1:
        all_func_hashes = set()
        last_directly_compiled = None
        for func_key in funcs:
            func = GLOBALS.function_resolver.get(func_key)
            all_func_hashes.add(func.hash)

            if func.was_directly_compiled:
                last_directly_compiled = func_key

        if len(all_func_hashes) == 1:
            # okay, all functions are really the same, but they have likely just been copied before compiling
            # just return the first but prefer ones that were directly compiled as they are what will be appearing
            # in the coverage reports
            return last_directly_compiled if last_directly_compiled else funcs[0]

        raise ValueError(f"Found multiple distinct functions with name {name}. Please be more specific. Options for fully specified names are: {funcs}")
    elif len(funcs) == 1:
        return GLOBALS.function_resolver.find_matching_index(funcs[0], scope='compiled', can_include_self=True)
    else:
        raise ValueError(f"Could not find any function matching {name}.")

# This can stay. Calls back to globals
def get_coverage_artifacts_dir():
    return GLOBALS.target.artifacts_dir

@tools.tool
def grep_sources(expression: str) -> str:
    '''
    Grep in the target sources for a given expression. This will return the output of
    `grep -rnE <expression>` of the source code folder which is rooted at `built_src/`.
    You can consider the `out/src/` folder equivalent to `/src/` in target paths.
    '''
    context = 0
    if context > 5:
        raise ValueError("You can not print more than 5 lines of context with each grep.")

    artifacts_dir = get_coverage_artifacts_dir()
    src_dir = Path(artifacts_dir) / 'out' / 'src'
    cmd = [
        'grep',
        '-C', str(context),
    ]
    cmd += [
        '--exclude-dir=' + 'out/src/aflplusplus',
        '--exclude-dir=' + 'out/src/honggfuzz',
        '--exclude-dir=' + 'out/src/libfuzzer',
        '--exclude-dir=' + 'out/src/shellphish',
    ]
    if int(os.environ.get('REPLICA_ID', '0')) % 2 == 0: # some replicas can access all files to increase visibility
        for suffix in VALID_SOURCE_FILE_SUFFIXES:
            cmd.append('--include=*' + suffix)
    cmd += [
        '-rnE',
        expression,
        'out/src'
    ]

    cmd_serialized = shlex.join(cmd)
    print("Running: " + repr(cmd_serialized))
    p = subprocess.Popen(cmd, cwd=artifacts_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    stdout = safe_decode_string(stdout)
    if len(stdout.split('\n')) > 200:
        stdout = stdout.split('\n')[:200] + ['... (limited output to 200 lines, if you need the rest, either reduce the context or be more specific in your expression)']
        stdout = '\n'.join(stdout)[:2000]
    stderr = safe_decode_string(stderr)
    output = f'''# SOURCE GREP RESULTS
The command `{cmd_serialized}` returned with exitcode {p.returncode}.
## STDOUT
```
{stdout}
```
## STDERR
```
{stderr}
```
'''
    return output

@tools.tool
def get_file_content(file: str, start_line: int, end_line: int) -> str:
    """
    Get a range of lines of a file from `out/src/`.
    This allows at most 200 lines to be returned at once to avoid excessive output.

    The `file` must be relative to the `out/src/` directory and must exist in the target sources.
    If the file does not exist, a ValueError will be raised.

    The argument `file` must be a valid file path relative to `out/src/`, and `start_line` and `end_line` must be 1-indexed.
    Negative values for `start_line` and `end_line` indicate counting from the end of the file (e.g., -1 for the last line).
    """
    artifacts_dir = get_coverage_artifacts_dir()
    src_dir = Path(artifacts_dir) / 'out' / 'src'
    file_path = src_dir / file
    if not file_path.exists():
        raise ValueError(f"File {file} does not exist in {src_dir} (it resolved to {file_path}).")

    with open(file_path, 'r') as f:
        lines = f.read().split('\n')

    if start_line == 0:
        raise ValueError("lines are 1-based, so this must be at least 1.")

    lines_considered = lines[start_line-1:end_line] if end_line > 0 else lines[start_line-1:end_line]
    lines_trimmed = lines_considered[:200]
    output = [
        f'{i:4d} | {line}' for i, line in enumerate(lines_trimmed, start=start_line + 1)
    ]
    output = '\n'.join(output)
    return f'''# FILE CONTENTS
The file `{file}` was found at `{file_path}`. The requested lines are from {start_line} to {end_line} (inclusive).
```
{output}
```
    {'... (limited output to 200 lines from '+ str(len(lines_trimmed)) + ' total lines)' if len(lines_trimmed) >= 200 else ''}
'''

@tools.tool
def get_files_in_directory(directory: str) -> List[str]:
    """
    Return a list of files in the directory `directory`. This is useful for finding the files in a directory to target with a grammar.

    The `directory` must be relative to the `out/src/` directory and must exist in the target sources.
    If the directory does not exist, a ValueError will be raised.
    Args:
        directory (str): The relative path of the directory (relative to `out/src/`).
    """
    artifacts_dir = get_coverage_artifacts_dir()
    src_dir = Path(artifacts_dir) / 'out' / 'src'
    dir_path = src_dir / directory
    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"Directory {directory} does not exist in {src_dir} (it resolved to {dir_path}).")

    files = subprocess.check_output(['ls', '-al', str(dir_path)], text=True).splitlines()
    log.info('[LLM-TOOL-CALL: get_files_in_directory] Found %d files in directory %r', len(files), directory)
    return f'# FILES IN DIRECTORY\nThe output of `ls -al {directory}` is:\n```\n' + '\n'.join(files) + '\n```'

@tools.tool
def get_functions_in_file(file: str) -> List[str]:
    """
    Return a list of functions in the file `file`. This is useful for finding the functions in a file to target with a grammar.

    The `file` must be relative to the `out/src/` directory and must exist in the target sources.
    If the file does not exist, a ValueError will be raised.
    Args:
        file (str): The relative path of the file (relative to `out/src/`). This does not support directories.
    """
    try:
        if file.startswith('oss-fuzz:'):
            file = file[len('oss-fuzz:'):]
        elif file.startswith('source:'):
            file = file[len('source:'):]

        functions = GLOBALS.function_resolver.find_by_filename(file)
        log.info('[LLM-TOOL-CALL: get_functions_in_file] Resolved functions in file %r to %r', file, functions)
        return f'# FUNCTIONS IN FILE\nThe functions found in `{file}` are:\n```\n' + '\n'.join(functions) + '\n```'
    except Exception as e:
        log.warning(f"Failed to get functions in file: {file}", exc_info=True)
        raise ValueError(f"ERROR: Failed to get functions in file: {file}. Error: {e}")

@tools.tool
def generate_inputs(grammar: str) -> List[bytes]:
    '''
    Generates 10 example inputs from a given grammar. ONLY use this function if you believe the generated input format does not match what you are expecting it to.
    You should always try to use `check_grammar_coverage` first before using this function and only use this if you believe the grammar does not produce the inputs you are expecting.
    '''
    try:
        if error := NautilusPythonGrammar.check_grammar(grammar):
            raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")

        g = NautilusPythonGrammar(grammar)
        inputs = []
        for inp in g.produce_input(10, unique=True):
            inputs.append(inp)
        return repr(inputs)
    except Exception as e:
        log.warning(f"Failed to generate inputs from grammar: \nGrammar: ```python\n{grammar}\n```\nError: {e}", exc_info=True)
        raise ValueError(f"ERROR: Failed to generate 10 inputs from grammar: {e}. The inputs it did generate were: {inputs!r}")

def get_coverage_report(grammar: str, *inputs, keys_of_interest=None):
    file_coverage: FileCoverageMap = GLOBALS.tracer.trace(*inputs)

    function_coverage: FunctionCoverageMap = GLOBALS.function_resolver.get_function_coverage(file_coverage)

    newly_reached_functions, newly_reached_files = register_grammar_coverage(grammar, file_coverage, function_coverage)

    report = ''
    if newly_reached_files:
        report += f'# SUCCESS: Newly reached files\n'
        report += '\n'.join([f'- {f}' for f in newly_reached_files]) + '\n'
        report += ' - REMEMBER to try to discover more interesting code based on these files and attempt to reach more code in these files.\n\n'

    report += GLOBALS.function_resolver.get_function_coverage_report(inputs, function_coverage, keys_of_interest)

    if newly_reached_functions:
        report += f'# SUCCESS: Newly reached functions\n'
        report += '\n'.join([f'- {f}' for f in newly_reached_functions]) + '\n'
        report += ' - REMEMBER to investigate these functions to see if they contain more interesting coverage to reach.\n\n'

    return report, newly_reached_files, newly_reached_functions

def get_crash_report(grammar: NautilusPythonGrammar, *inputs, losan: bool = True, include_seeds_repr: bool = False):
    '''
    Check if inputs produced by the grammar cause crashes in the target application. Get information about the crashes and the LOSAN metadata of the inputs that crashed.
    '''


    losan_target = GLOBALS.losan_target
    if losan_target is None:
        return None, [], []
    out_report = '# CRASH REPORTS\n'
    deduped_reports = set()
    crashing_inputs = []
    losan_crashing_inputs = []
    all_losan_metadatas = set()
    for i, input in enumerate(inputs):
        out_report += '\n\n## Input {}\n'.format(i)
        out_report += f'Crashing Input: `{input.read_bytes()!r}`\n'
        try:
            pov_result = losan_target.run_pov(GLOBALS.cp_harness_name, data_file=input, losan=True)
        except Exception as e:
            out_report += f'Error while processing input: {input!r}. Error: {e}\n'
            continue
        if pov_result.pov.exception:
            out_report += 'Crash parsing failed with the following error, but the target probably crashed:\n'
            out_report += f'Unparsed report: ```{pov_result.pov.unparsed}```\n'
            crashing_inputs.append(input)
        elif pov_result.pov.parser == 'failed' and pov_result.pov.unparsed:
            out_report += 'No crash report found, the target probably did not crash.\n'
            lines_with_exceptions = b"\n".join([l for l in pov_result.pov.unparsed.split(b'\n') if b'Exception' in l][-10:])
            unparsed_lines = b"\n".join(pov_result.pov.unparsed.split(b'\n')[-10:])
            out_report += f'```### Exception Lines\nWe\'ve found the following lines with exceptions in the unparsed report:\n{lines_with_exceptions}```\n'
            out_report += f'```### Unparsed Lines\nHere are the last 10 lines of the unparsed report:\n{unparsed_lines}```\n'
        elif not pov_result.pov.crash_report:
            out_report += 'No crash report was generated. The target probably did not crash.\n'
        else:
            if pov_result.pov.crash_report.losan:
                losan_crashing_inputs.append(input)
            else:
                crashing_inputs.append(input)
            deduped_reports.add(yaml.dump(pov_result.pov.dedup_crash_report.model_dump()))
            out_report += 'Crash report:\n'
            out_report += f'```{safe_decode_string(pov_result.pov.crash_report.raw_report)}```\n'
            if pov_result.pov.crash_report.losan_metadata:
                all_losan_metadatas.add(pov_result.pov.crash_report.losan_metadata.description())
                out_report += 'LOSAN Metadata (Your task is completed if the expected value here matches the seen one.):\n'
                out_report += f'```{pov_result.pov.crash_report.losan_metadata.description()}```\n'

    if all_losan_metadatas:
        out_report += '\n\n# LOSAN Metadata Summary:\n'
        out_report += 'We\'ve found the following unique LOSAN Metadata reports:\n'

        for losan_metadata in all_losan_metadatas:
            out_report += f'- {losan_metadata}\n'

    return out_report, crashing_inputs, losan_crashing_inputs

def produce_grammar_inputs(grammar: str, output_dir, n_inputs: int = 20, error_if_too_restrictive: bool = True):
    if error := NautilusPythonGrammar.check_grammar(grammar):
        raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")

    g = NautilusPythonGrammar(grammar)
    inputs = list(g.produce_input_files(n_inputs, output_dir=Path(output_dir), unique=True))
    if len(inputs) < (n_inputs // 2) or not len(inputs):
        first_inputs = [i.read_bytes() for i in inputs[:3]]
        if len(inputs) == 0:
            msg_error = 'No inputs were generated.'
        elif len(inputs) <= 3:
            msg_error = f'Only {len(inputs)} inputs were generated. Here are the inputs it generated: {first_inputs}.'
        else:
            msg_error = f'Only {len(inputs)} inputs were generated. Here are a few of the inputs it generated: {first_inputs}.'
        raise ValueError(f"ERROR: The grammar is too restrictive: It didn't even generate half of the {n_inputs} required inputs. ({msg_error}). YOU ARE NOT ALLOWED TO SUBMIT THIS GRAMMAR.")

    return inputs

def resolve_functions_to_check(funcs: List[str]) -> List[FUNCTION_INDEX_KEY]:
    result = []
    errored_funcs = {}
    for needle in funcs:
        try:
            result.append(resolve_function_name(needle))
        except ValueError as e:
            errored_funcs[needle] = str(e)
    if errored_funcs:
        raise ValueError(f"ERROR: Could not resolve the following functions: {errored_funcs}.")
    return result

@tools.tool
def check_grammar_coverage(grammar: str, target_function: str):
    '''
    Generates a line coverage report showing which lines of the specified `target_function` are exercised by inputs produced from the given `grammar`.
    :param `grammar` (required): A grammar specification in the nautilus python format.
    :param `target_function` (required): A fully qualified function name for which coverage should be evaluated, for example the target function
    :return A string that contains a line coverage report for the given grammar and function to check.
    '''
    try:
        if error := NautilusPythonGrammar.check_grammar(grammar):
            raise ValueError(f"ERROR: The specified grammar was not valid:\n```\n{error}\n```")
    except Exception as e:
        log.warning(f"The grammar was invalid.\nGrammar: ```python\n{grammar}\n```", exc_info=True)
        raise

    try:
        keys_of_interest = resolve_functions_to_check([target_function])
        harness_index = GLOBALS.harness_function_index_key
        if harness_index not in keys_of_interest:
            keys_of_interest.append(harness_index)
    except Exception as e:
        log.warning(f"Failed to resolve functions to check: {target_function}", exc_info=True)
        raise ValueError(f"ERROR: Failed to resolve functions to check: {target_function}. Error: {e}")
    try:
        with tempfile.TemporaryDirectory() as output_dir:
            inputs = produce_grammar_inputs(grammar, output_dir, n_inputs=20, error_if_too_restrictive=True)

            cov_report, newly_reached_files, newly_reached_functions = get_coverage_report(grammar, *inputs, keys_of_interest=keys_of_interest)
            if newly_reached_files or newly_reached_functions:
                save_new_fuzzer_inputs('nautilus-python', grammar, inputs, newly_reached_files=newly_reached_files, newly_reached_functions=newly_reached_functions)
            crash_report, crashing_inputs, losan_crashing_inputs = get_crash_report(grammar, *inputs)
            if crashing_inputs:
                save_new_crashing_inputs(grammar, crashing_inputs)
            if losan_crashing_inputs:
                save_new_losan_crashing_inputs(grammar, losan_crashing_inputs)
            final_report = f'# COVERAGE REPORT\n{cov_report}'
            if crashing_inputs:
                final_report += f'# CRASH REPORT\nThe following crash report was found for the discovered inputs: {crash_report}'
            return final_report
    except Exception as e:
        log.warning(f"Failed to check grammar coverage.\nGrammar: ```python\n{grammar}\n```", exc_info=True)
        raise

@tools.tool
def set_target_function(target_function: str): 
    '''
    Sets the target function for improvement and coverage collection.
    '''
    TARGET_FUNCTION_KEY = target_function
    if not TARGET_FUNCTION_KEY:
        raise ValueError("ERROR: Target function must be specified.")
    return f"Set target function to {TARGET_FUNCTION_KEY}."

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
            
            file_coverage: FileCoverageMap = GLOBALS.tracer.trace(*inputs)
            function_coverage: FunctionCoverageMap = GLOBALS.function_resolver.get_function_coverage(file_coverage, function_keys_of_interest=[TARGET_FUNCTION_KEY])
            
            register_grammar_coverage(grammar, file_coverage, function_coverage)
            lines_covered = [l for l in function_coverage.get(TARGET_FUNCTION_KEY, []) if l.count_covered and l.count_covered > 1]

            if not lines_covered:
                raise ValueError(f"ERROR: The grammar does not hit the target function.")

    except Exception as e:
        import traceback; traceback.print_exc()
        raise ValueError(f"ERROR: Failed to validate grammar: {e}")

    print(f"Successfully submitted grammar: {grammar}")
    raise tools.ToolSignal()

@tools.tool
def find_function(name: str) -> Tuple[str, str]:
    """
    Return information about the function named `name`. Includes metadata as well as the source code if found.
    If you already have a fully specifified name, always use that to avoid ambiguity.
    """
    try:
        key = resolve_function_name(name)
        entry = GLOBALS.function_resolver.get(key)
        return f'''
# {entry.target_container_path}:{entry.start_line} for {key}
<code>
{entry.code}
</code>
'''
    except Exception as e:
        log.warning(f"Failed to find function: {name}", exc_info=True)
        raise ValueError(f"ERROR: Failed to find function: {name}. Error: {e}")
    
GLOBALS.memories = []

@tools.tool
def remember(message: str):
    '''
    Remembers a message for future reference. Your memories must be short and succinct as they are limited to 256 characters each.
    Furthermore, you can only remember up to 10 messages. Make sure to use this tool wisely and to only remember crucial pieces
    of information.
    '''
    
    if len(GLOBALS.memories) >= 10:
        raise ValueError("You can only remember up to 10 messages.")
    if len(message) > 256:
        raise ValueError("Your memory must be less than 100 characters.")
    GLOBALS.memories.append(message)
    return "Remembered: " + message
