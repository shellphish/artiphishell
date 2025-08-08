import os
import logging
import re
import hashlib
import json
import random
import difflib
import pathlib
import math
from typing import List
import tiktoken
import subprocess

from grammar_guy.common import config
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.models.coverage import CoverageLine, FunctionCoverageMap, LinesCoverage, FunctionCoverage
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY

log = logging.getLogger("grammar_guy")

# ----- Coverage utils -----

def log_grammar_changes(grammar_path: pathlib.Path, gg_source: pathlib.Path) -> None:
    ''' Log the changes made to the grammar of "target"
    :param str target: the name of the target whose grammar changes shall be logged
    :return: None
    '''
    try:
        subprocess.run(['./scripts/log_changes.sh', str(grammar_path)], cwd=gg_source, check=True)
    except subprocess.CalledProcessError as e:
            log.error(f"An error occurred: {e}, \n Standard Error: {e.stderr}")
            raise e

def diff_function_coverage(function_cov_paths: tuple) -> str:
    ''' Get tuple of paths for old and new coverage files and diffs the files in the directory
    '''
    if function_cov_paths[1] == "Initial iteration":
        log.warning("No previous coverage to diff with")
        return {'No previous coverage': 'Initial Iteration'}
    assert(os.path.exists(function_cov_paths[0]))
    assert(os.path.exists(function_cov_paths[1]))

    num_old = len(os.listdir(function_cov_paths[0]))
    num_new = len(os.listdir(function_cov_paths[1]))

    old_path = function_cov_paths[0]
    new_path = function_cov_paths[1]

    # changed to list to make handling easier
    diff_list = []
    if num_old != num_new:
        log.error('Rethink your life if this case appears. You can apparently not read code.')

    for old_file in os.listdir(old_path):
        for new_file in os.listdir(new_path):
            if old_file == new_file:
                with open(old_path + f"/{old_file}", "r") as old_f:
                    with open(new_path + f"/{new_file}", "r") as new_f:
                        # fix when time at hand. Just sticked to the example.
                        old_lines = old_f.read()
                        new_lines = new_f.read()
                        old_lines = re.sub(r'\x1b\[.*?m', '', old_lines)
                        new_lines = re.sub(r'\x1b\[.*?m', '', new_lines)

                        line_diff = difflib.ndiff(old_lines.splitlines(keepends=True), new_lines.splitlines(keepends=True))
                        line_diff = ''.join(line_diff)

                        diff_list.append(line_diff)
    return diff_list

def is_covered_function(cov_lines: LinesCoverage):
    ''' Takes single coverage entry & checks if function coverage is 0 everywhere
    :param dict function_coverage: the parsed function coverage file
    :return: boolean
    '''
    covered, uncovered = get_covered_uncovered_lines(cov_lines)
    if len(covered) != 0:
        return True
    return False

def get_covered_uncovered_lines(cov_lines: LinesCoverage):
    ''' Takes parsed coverage dict for one function and returns the lines that were covered and uncovered
    :param: function_cov_dict: the parsed coverage dictionary for one function
    :return: a tuple with lists of (covered, uncovered)
    '''
    covered_lines = []
    uncovered_lines = []
    for cov_line in cov_lines:
        assert cov_line.count_covered is None or isinstance(cov_line.count_covered, int), f"Count is not an integer: {cov_line.count_covered}"
        if cov_line.count_covered is None:
            continue
        if cov_line.count_covered > 0:
            covered_lines.append(cov_line.line_number)
        if cov_line.count_covered == 0:
            uncovered_lines.append(cov_line.line_number)
    return covered_lines, uncovered_lines

def is_improvable_function(covered_lines, uncovered_lines):
    return covered_lines and uncovered_lines

def get_functions_called_in_function(function_key: FUNCTION_INDEX_KEY) -> List[FUNCTION_INDEX_KEY]:
    '''
    Get the function index keys for all functions called in the given function `function_key`.
    :param function_key: the function key for which to get the called functions
    :return: a list of function index keys for all functions called in the given function
    '''
    called_functions = []
    func_index_entry = config.FUNCTION_RESOLVER.get(function_key)
    for fun_key in config.LIST_OF_FUNCTIONS:
        func_name = config.FUNCTION_RESOLVER.get_funcname(fun_key)
        if func_name in func_index_entry.code:
            called_functions.append(fun_key)
    return called_functions

def get_uncovered_functions_called_in_function(coverage_by_function: FunctionCoverageMap, function_key: FUNCTION_INDEX_KEY):
    return filter_uncovered_functions(get_functions_called_in_function(function_key), coverage_by_function)

def filter_uncovered_functions(fun_list: List[FUNCTION_INDEX_KEY], coverage_by_function: FunctionCoverageMap):
    uncovered_functions = []
    for fun in fun_list:
        if not is_covered_function(coverage_by_function[fun]):
            uncovered_functions.append(fun)
    return uncovered_functions

def filter_uncovered_functions(fun_list: List[FUNCTION_INDEX_KEY], coverage_by_function: FunctionCoverageMap):
    uncovered_functions = []
    for fun in fun_list:
        if is_covered_function(coverage_by_function.get(fun, [])):
            uncovered_functions.append(fun)
    return uncovered_functions

# ----- File operations -----

def remove_excess_files(num_unique_files, num_desired_files):
    num_excess_files = num_unique_files - int(num_desired_files)
    for _ in range(0, num_excess_files):
        to_be_removed = random.choice(os.listdir(str(config.generated_inputs_path())))
        try:
            subprocess.run(['rm', f'{to_be_removed}'], cwd=str(config.generated_inputs_path()), check=True)
        except subprocess.CalledProcessError as e:
            raise ChildProcessError(f"Could not remove file {to_be_removed} @ {str(config.generated_inputs_path())} \n {e}")

def remove_all_generated_files():
    cleanup_tmp_hashes()
    for f in os.listdir(str(config.generated_inputs_path())):
        os.unlink(str(config.generated_inputs_path() / f))

def cleanup_tmp_hashes():
    try:
        subprocess.run(['rm', '-rf', f'tmp_hashes'], cwd=str(config.generated_inputs_path()), check=True)
    except subprocess.CalledProcessError as e:
        # FIXME: should not raise assertion but return False and then handle ?
        raise ChildProcessError(f"Could not remove tmp_hashes folder @ {str(config.generated_inputs_path())}")
    return True

def remove_old_grammar():
    try:
        os.remove(str(config.grammar_path() / f"spearfuzz{config.grammar_type()}"))
    except FileNotFoundError:
        log.warning("NON FATAL: No old grammar to remove")

def clear_input_directory():
    '''
    Clears all inputs from config.generated_inputs_path()
    '''
    cleared_count = 0
    assert(os.path.isdir(config.generated_inputs_path()))
    for file in os.listdir(config.generated_inputs_path()):
        cleared_count += 1
        os.remove(config.generated_inputs_path() /  f"{file}")
    log.info(f"🧹 Cleaned {cleared_count} files from input.")

def split_grammar_from_message(grammar: str):
    ''' Splits the grammar from the given string
    :param str grammar: the grammar string
    :return: the grammar string or None if not found
    '''
    split_grammar: list = grammar.split({
        'grammarinator': '```antlr',
        'nautilus': '```python',
    }[config.FUZZER_NAME])
    if config.FUZZER_NAME == 'grammarinator' and 'grammar spearfuzz' not in grammar:
        raise AssertionError(f"Grammar not found in grammar string {grammar}")

    grammar: str=""
    for i in split_grammar:
        if config.FUZZER_NAME == 'grammarinator':
            if f"grammar spearfuzz" in i:
                grammar = i
        else:
            grammar = i

    grammar = grammar.split("```")[0]
    return grammar

def split_grammars_from_multi_grammar_message(grammar_message: str):
    ''' Splits multiple grammars from the given string
    :param str grammar_message: the grammar message string
    :return: a list of grammar strings
    '''
    split_grammar: list = grammar_message.split({
        'grammarinator': '```antlr',
        'nautilus': '```json',
    }['nautilus'])

    grammars = []
    for i in split_grammar:
        if config.FUZZER_NAME == 'grammarinator':
            if f"grammar spearfuzz" in i:
                grammars.append(i.split("```")[0])
        else:
            grammars.append(i.split("```")[0])

    return grammars[1:]

def save_inputs_and_grammar(grammar_type: str, grammar: str, seeds: List[pathlib.Path], newly_reached_functions: List[FUNCTION_INDEX_KEY], newly_reached_files: List[str], **kwargs) -> None:
    """
    Save new fuzzer inputs to the fuzzer sync directory. The inputs are named based on the grammar and the seed name."
    These inputs are saved because they first newly reached the given files and functions."
    """
    pc = config.get_permanence_client()
    if pc is not None: # removed coverage tracer check.
        try:
            pc.seeds_reached(
                project_name=config.PROJECT_HARNESS_METADATA['project_name'],
                harness_name=config.CP_HARNESS_NAME,
                seeds=[seed.read_bytes() for seed in seeds],
                hit_functions=newly_reached_functions,
                hit_files=newly_reached_files,
                grammar_type=grammar_type,
                grammar=grammar,
                **kwargs,
            )
        except Exception as e:
            log.warning(f"Error while immortalizing function-reaching seeds: {e}")
        try:
            pc.grammar_reached(
                project_name=config.PROJECT_HARNESS_METADATA['project_name'],
                harness_name=config.CP_HARNESS_NAME,
                grammar_type=grammar_type,
                grammar=grammar,
                hit_functions=newly_reached_functions,
                hit_files=newly_reached_files,
                **kwargs,
            )
        except Exception as e:
            log.warning(f"Error while immortalizing function-reaching grammars: {e}")
    # Wrapped in for loop. Changed sync_dir to seed_sync_dir.
    for sync_directory in config.get_fuzzer_sync_dirs():
        # Sync the seeds
        seeds_sync_dir = sync_directory / 'queue'
        seeds_sync_dir.mkdir(parents=True, exist_ok=True)
        count_previous = len(os.listdir(seeds_sync_dir))
        grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
        for i, seed in enumerate(seeds):
            seed_name = seed.name
            seed_path = seeds_sync_dir / 'id:{:06d},grammar_src:{}-{}'.format(count_previous, grammar_hash, seed_name)
            seed_path.write_bytes(seed.read_bytes())
            count_previous += 1

        # Sync the grammar
        grammar_sync_dir = sync_directory / '..' / 'sync-grammars' / grammar_type
        grammar_sync_dir.mkdir(parents=True, exist_ok=True)
        extension = '.py' if grammar_type == 'nautilus-python' else '.json'
        grammar_path = grammar_sync_dir / 'guy_grammar_{}{}'.format(grammar_hash, extension)
        if not grammar_path.exists():
            grammar_path.write_text(grammar, encoding='utf-8')

def read_grammar(grammar_file_path):
    ''' Reads file and hands it to split_grammar_from_message
    :param str grammar_file_path: path to the file containing the grammar
    :return: grammar string or None if not found'''
    assert(os.path.isfile(grammar_file_path))

    grammar=""
    with open(grammar_file_path, "r") as f:
        try:
            grammar = f.read()
        except Exception as e:
            log.info("Could not read grammar file")
            raise AssertionError(f"Grammar not found @ {grammar_file_path}")
    return split_grammar_from_message(grammar)

def write_to_file(filepath, filename:str, content:str , write_mode:str = "w") -> None:
    ''' Write content to a file
    :param str filepath: path to file to write to
    :param str content: content to write to the file
    :param str write_mode: the write mode to use (default: "w+")
    '''
    log.info(f"GG: Writing grammar")
    log.debug(f"📝 Writing grammar \n {content} \n to {filepath}")
    if not os.path.exists(str(filepath)):
        log.info(f"GG: Creating directory in write_file: {str(filepath)}")
        os.makedirs(str(filepath))

    with open(str(filepath) + f"/{filename}", write_mode) as f:
        try:
            f.write(content)
            f.close()
        except Exception as e:
            raise IOError(f"Could not write to file {filename} @ {filepath} \n Exception {e}")

def move_files_to_afl_dir(source_dir: pathlib.Path) -> None:
    ''' Rename files to global AFL_SYNC_COUNT + 1 and copy from source to AFL directory
    :param pathlib.Path source_dir: the source directory
    :return: Boolean value that indicate success or failure
    '''
    assert os.path.exists(source_dir), f"Source directory {source_dir} does not exist"
    assert all(os.path.exists(path) for path in config.get_fuzzer_sync_dirs()), f"One or more AFL directories in {config.get_fuzzer_sync_dirs()} do not exist"

    local_copy_count = 0
    for fuzzer_sync_dir in config.get_fuzzer_sync_dirs():
        for file in os.listdir(source_dir):
            new_file_name = f"id:{str(config.get_afl_sync_count()).zfill(6)}_{file}"
            config.increment_sync_count()
            res = subprocess.run(['mv', str(source_dir) + f"/{file}", str(fuzzer_sync_dir) + f"/queue/{new_file_name}"], capture_output=True, text=True)
            if res.returncode != 0:
                pass
                log.warning(f"Could not sync file {file} to FUZZER directory: ")
                log.warning(f"Error: {res.stderr}")
            else:
                local_copy_count += 1
    log.info(f"Synced {local_copy_count} files to FUZZER directories \n TOTAL SEEDS SYNCED: \
                # {config.get_afl_sync_count()} \n\n FUZZER SYNC DIRS [{', '.join(str(path) for path in config.get_fuzzer_sync_dirs())}]")

# ----- LLM Garbage -----

def set_encoding_model(model_name: str):
    enc = tiktoken.encoding_for_model(model_name)
    return enc

def check_token_limit(llm_arguments: list, token_limit= 110000, model_name: str = "gpt-4o"):
    '''Returns True if tokenlimit exceeded
    :param list llm_arguments: list of arguments to encode
    :param int token_limit: the token limit
    :param str model_name: the model name to use
    :return: boolean (True if token limit exceeded)
    '''
    total_tokens = 0
    enc = set_encoding_model(model_name)
    try:
        encoded_source = enc.encode_batch(llm_arguments)
        total_tokens = sum([len(x) for x in encoded_source])
    except: 
        return True
    if total_tokens > token_limit:
        log.warning(f"GG (check_token_limit): Token limit exceeded - got {total_tokens} tokens")
        return True
    else:
        log.warning(f"GG (check_token_limit): Token limit not exceeded - got {total_tokens} tokens")
        return False

def iteration_heat(iteration, max_retries: int):
    iteration_heat = 0
    if iteration < max_retries / 2:
        iteration_heat = 0.0
    if iteration > math.floor(max_retries / 2):
        iteration_heat = 0.1
    return iteration_heat

def run_temperature(iteration, penalty, max_retries: int):
    temperature = 0.0 + iteration_heat(iteration, max_retries)
    temperature += (penalty * abs(iteration - max_retries))
    if temperature > 1.0:
        log.warning("Temperature over 1 - NOT ALLOWED. Setting to 0.99")
        temperature = 0.99
    elif temperature < 0.0:
        log.warning("Temperature less than 0 - NOT ALLOWED. Setting to 0.1")
        temperature = 0.1
    return temperature

def get_sarif_function_of_interest() -> List[FUNCTION_INDEX_KEY]:
    func_of_interest = []
    for codeflow in config.get_sarif_results().codeflows:
        for location in codeflow.locations:
            if location.keyindex not in func_of_interest:
                func_of_interest.append(location.keyindex)
    if len(func_of_interest) == 0:
        log.warning("No functions of interest found in SARIF results. Exiting.")
        return "None"
    return func_of_interest
# ----- Web View -----

def set_up_webview():
    grammars_dir = config.stats_dir() / "grammars"
    grammars_dir.mkdir(parents=True, exist_ok=True)
    target_func_cov_path = grammars_dir / "target_func_cov.json"
    with open(target_func_cov_path, "w") as f:
        target_func_cov = []
        json.dump(target_func_cov, f)
