from contextlib import contextmanager
from typing import Dict, Optional
import argparse
import hashlib
import pathlib
import json
import time
import os
import yaml

from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import OSSFuzzProjectYAML, LanguageEnum, AugmentedProjectMetadata
from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap

from shellphish_crs_utils import sarif_resolver
from coveragelib import Tracer
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco

from permanence.client import PermanenceClient

# ------------------- GLOBAL VARIABLES --------------------
FUNCTIONS_INDEX_PATH= None
JSONS_DIR_PATH= None
HARNESS_INFO_PATH= None
NEW_REPORT = None

TARGET_PROJECT = None
CRASH_REPORT_PATH=None
INPUT_FINAL_DESTINATION=None
LIST_OF_FUNCTIONS = None
MODEL= None
NUM_INPUT= None
GG_SOURCE= None
STATS_DIR = None
FUZZER_NAME = None
HARNESS_INFO_ID: str = None
NEW_GRAMMAR = None
#
FUNCTIONS_INDEX = None
HARNESS_INFO: HarnessInfo = None
FUNCTIONS_INDEX = None

PROJECT_METADATA: AugmentedProjectMetadata = None

COVERAGE_TRACER = None
FUNCTION_RESOLVER = None
FUZZER_SYNC_DIRS = []
PERMANENCE_CLIENT = None
NEXT_GRAMMAR_ID = 0
SARIF_MODE = False
SARIF_RESOLVER = None
SARIF_PATH = None
SARIF_RESULTS = None

# NEW GLOBALS
PROJECT_HARNESS_METADATA = None

CP_HARNESS_NAME = ''
PROJECT_HARNESS_METADATA_ID = ''
TARGET_SHARED_DIR = []
HARNESS_INFO_FILES = []
HARNESS_INFO_DICT = {}
EVENTS_DIR = ''
# ------------------- ARGUMENT PARSING --------------------

def parse_config_from_args():
    global AFL_SYNC_COUNT
    global COVERAGE_TRACER
    global CRASH_REPORT_PATH
    global FUZZER_NAME
    global FUZZER_SYNC_DIRS
    global FUNCTIONS_INDEX
    global FUNCTIONS_INDEX_PATH
    global FUNCTION_RESOLVER
    global GG_SOURCE
    global GRAMMAR_TYPE
    global HARNESS_INFO
    global HARNESS_INFO_ID
    global HARNESS_INFO_PATH
    global IMPROVEMENT_STRATEGIES
    global INPUT_FINAL_DESTINATION
    global INPUT_GENERATED_TOTAL
    global JSONS_DIR_PATH
    global LIST_OF_FUNCTIONS
    global MODEL
    global NUM_INPUT
    global PERMANENCE_CLIENT
    global PROJECT_METADATA
    global SARIF_MODE
    global SARIF_PATH
    global SARIF_RESOLVER
    global SARIF_RESULTS
    global STATS_DIR
    # New global declarations
    global PROJECT_HARNESS_METADATA
    global CP_HARNESS_NAME
    global PROJECT_HARNESS_METADATA_ID
    global TARGET_SHARED_DIR
    global HARNESS_INFO_FILES
    global HARNESS_INFO_DICT
    global EVENTS_DIR

    parser = argparse.ArgumentParser(prog='GrammarGuy', description='Fuzzes the thing', epilog='hehe fuzzing go sprrrrrrr')
    parser.add_argument('--project-metadata', type=pathlib.Path, help='The project metadata', required=True)
    parser.add_argument('-n', '--num_input', help='The number of inputs created for each iteration of grammar improvement', default=300)
    parser.add_argument('-m', '--model', help='The model to use', default='gpt-3.5-turbo') # TODO change me back when done testing

    # Path arguments
    parser.add_argument('-t', '--target', help='The target source path', required=True)
    parser.add_argument('-idx', '--function_index_path', help='Full function index file path', required=True)
    parser.add_argument('-cr', '--crash_report_path', help='The path to the crash report', default="nah boi i aint got no crash report")
    parser.add_argument('-jd', '--json_dir_path', help='The path to the functions JSON directory', required=True)
    parser.add_argument('-src', '--gg_source', help='The path to the grammar guy source', default="/shellphish/grammar_guy/src/")
    parser.add_argument('-f', '--functions', help='The list of functions (a json file)', default=None)
    parser.add_argument("-s", "--stats-dir", help="The directory to store the stats")
    parser.add_argument("-fuzz", "--fuzzer-name", help="The name of the fuzzer", default='nautilus', choices=['grammarinator', 'nautilus'])
    parser.add_argument('-sarif', '--sarif_path', help="Set if running in SARIF mode", default=False)
    # New arguments
    parser.add_argument('--target-split-metadata', type=pathlib.Path, help='The target split metadata file', required=True)
    parser.add_argument('--project-harness-metadata-id', help='The id of the project harness metadata', required=True)
    parser.add_argument('--project-harness-metadata', type=pathlib.Path, help='The project harness metadata file', required=True)
    # parser.add_argument('--build-artifact-dir', help='Directory that contains the build artifact for the harness', required=True)
    parser.add_argument('--events-dir', type=pathlib.Path, help='Directory to store events', required=False, default='./events')

    args = parser.parse_args()
    with open(args.project_metadata, 'r') as f:
        PROJECT_METADATA = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
    set_target_project(args.target)
    FUNCTIONS_INDEX_PATH = pathlib.Path(args.function_index_path)
    JSONS_DIR_PATH = pathlib.Path(args.json_dir_path)
    CRASH_REPORT_PATH = pathlib.Path(args.crash_report_path)
    LIST_OF_FUNCTIONS = pathlib.Path(args.functions) if args.functions else None
    SARIF_PATH = pathlib.Path(args.sarif_path) if args.sarif_path else None
    STATS_DIR = pathlib.Path(args.stats_dir)

    AFL_SYNC_COUNT = 0
    INPUT_GENERATED_TOTAL = 0
    
    print(f"STATS_DIR: {STATS_DIR}")
    MODEL = args.model
    NUM_INPUT = args.num_input
    FUZZER_NAME = args.fuzzer_name
    GG_SOURCE = pathlib.Path(args.gg_source)
    IMPROVEMENT_STRATEGIES = ['extender', 'random', 'uncovered_callable_function_pairs']

    if FUZZER_NAME == 'nautilus':
        GRAMMAR_TYPE = ".py"

    # New parsed variables
    with open(args.target_split_metadata, 'r') as f:
        TARGET_SPLIT_METADATA = yaml.safe_load(f)
        PROJECT_HARNESS_METADATA = TARGET_SPLIT_METADATA['project_harness_metadatas'][args.project_harness_metadata_id]
    
    for harness_info_id, harness_info in TARGET_SPLIT_METADATA['harness_infos'].items():
            # GET might break because of missing values - not list in pydantic model
            if harness_info['cp_harness_name'] == PROJECT_HARNESS_METADATA['cp_harness_name']:
                hi = HarnessInfo.model_validate(harness_info)
                HARNESS_INFO_FILES.append(hi)
                HARNESS_INFO_DICT[harness_info_id] = hi
    PROJECT_HARNESS_METADATA_ID = args.project_harness_metadata_id
    CP_HARNESS_NAME = PROJECT_HARNESS_METADATA['cp_harness_name']
    set_directories()

    # asserts for all the paths above
    assert FUNCTIONS_INDEX_PATH.exists(), f"Function index file does not exist at {FUNCTIONS_INDEX_PATH}"
    assert JSONS_DIR_PATH.exists(), f"JSON directory does not exist at {JSONS_DIR_PATH}"
    assert TARGET_PROJECT is not None, f"Target does not exist at {args.target}"
    assert GG_SOURCE.exists(), f"Grammar guy source does not exist at {GG_SOURCE}"

    if input_list_of_functions():
        with open(str(input_list_of_functions()), 'r') as f:
            LIST_OF_FUNCTIONS = yaml.safe_load(f)["target_functions"]

    # with open(str(harness_info_path()), 'r') as f:
    #     HARNESS_INFO = HarnessInfo.model_validate(yaml.safe_load(f))
        
    FUNCTION_RESOLVER = RemoteFunctionResolver(PROJECT_HARNESS_METADATA['project_name'], PROJECT_HARNESS_METADATA['project_id'])


    if SARIF_PATH and SARIF_PATH != '':
        assert SARIF_PATH.exists(), f"SARIF path does not exist at {SARIF_PATH}"
        SARIF_MODE = True
    else: 
        if LIST_OF_FUNCTIONS:
            LIST_OF_FUNCTIONS = list(set([i for i in LIST_OF_FUNCTIONS if i in FUNCTION_RESOLVER.keys()]))
        else:
            LIST_OF_FUNCTIONS = list(FUNCTION_RESOLVER.keys())

# ------------- GETTER and SETTER FUNCTIONS --------------------
def get_afl_sync_path():
    return AFL_SYNC_PATH

def get_afl_sync_count():
    return AFL_SYNC_COUNT

def get_permanence_client() -> Optional[PermanenceClient]:
    """
    Returns a PermanenceClient instance with the current function resolver and fuzzer sync directory.
    """
    global PERMANENCE_CLIENT
    func_resolver = FUNCTION_RESOLVER
    if PERMANENCE_CLIENT is None and func_resolver is not None: 
        PERMANENCE_CLIENT = PermanenceClient(
            function_resolver=func_resolver
        )

    return PERMANENCE_CLIENT

def get_output_format_path(grammar_type):

    if grammar_type == 'nautilus-python':
        assert os.path.exists('/shellphish/grammar_guy/src/grammar_guy/common/agents/prompts/nautilus/grammar.output.txt') 
        return '/shellphish/grammar_guy/src/grammar_guy/common/agents/prompts/nautilus/grammar.output.txt'
    else:
        raise ValueError(f"Unknown grammar type: {grammar_type}. Supported types are: 'nautilus-python'.")

def get_input_generated_total():
    return INPUT_GENERATED_TOTAL

def increment_sync_count():
    global AFL_SYNC_COUNT
    AFL_SYNC_COUNT += 1

def get_sync_count():
    return AFL_SYNC_COUNT

def get_new_grammar():
    return NEW_GRAMMAR

def set_new_grammar(grammar):
    global NEW_GRAMMAR 
    NEW_GRAMMAR = grammar

def get_new_report(): 
    return NEW_REPORT

def set_new_report(report):
    global NEW_REPORT
    NEW_REPORT = report

def get_harness_src():
    global PROJECT_METADATAs
    
    full_path = TARGET_PROJECT.get_harness_source_artifacts_path(CP_HARNESS_NAME, FUNCTION_RESOLVER)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Harness source artifacts path '{full_path}' does not exist.")
    with open(full_path, 'r') as f:
        return f.read()

def get_sarif_results(): 
    return SARIF_RESULTS

def get_fuzzer_sync_dir():
    return FUZZER_SYNC_DIR

def set_target_project(path):
    global TARGET_PROJECT

    TARGET_PROJECT = InstrumentedOssFuzzProject(CoverageFastInstrumentation(), path, augmented_metadata=PROJECT_METADATA)
    # mostly for debugging now, we rebuild the images to make sure they exist. In the pipeline they *should* be cached
    TARGET_PROJECT.build_builder_image()
    TARGET_PROJECT.build_runner_image()

    os.makedirs(TARGET_PROJECT.artifacts_dir_work / 'grammar', exist_ok=True)

def get_function_index(list_of_functions) -> Dict[str, FunctionIndex]:
    log_event(
        "get_function_index",
        {
            "list_of_functions": list_of_functions
        }
    )
    fun_index = {}
    with open(str(functions_index_path()), 'r') as f:
        function_index_json = json.loads(f.read())
        for key in function_index_json.keys():
            if list_of_functions is not None and not any([fun_name in key for fun_name in list_of_functions]):
                continue
            with open(str(jsons_dir_path() / function_index_json[key]), 'r') as fo:
                function_json_dict = FunctionIndex.model_validate_json(fo.read())
                fun_index[key] = function_json_dict
    return fun_index

# ------------ FILE PATHS AND COMMON OBJECTS --------------------

def input_final_destination():
    return INPUT_FINAL_DESTINATION

def input_list_of_functions():
    return LIST_OF_FUNCTIONS

def generated_inputs_path():
    return TARGET_PROJECT.artifacts_dir_work / 'inputs'

def functions_index_path():
    return FUNCTIONS_INDEX_PATH

def jsons_dir_path():
    return JSONS_DIR_PATH

def harness_info_path():
    return HARNESS_INFO_PATH

def crash_report_path():
    return CRASH_REPORT_PATH

def sar_resolver(): 
    return SARIF_RESOLVER

def grammar_path():
    return TARGET_PROJECT.artifacts_dir_work / 'grammar' # / "spearfuzz.g4"

def gg_source():
    return GG_SOURCE

def num_input():
    return NUM_INPUT

def grammar_type():
    return GRAMMAR_TYPE

def stats_dir() -> pathlib.Path:
    return STATS_DIR

def improvement_strategies():
    return IMPROVEMENT_STRATEGIES

def record_grammar_success(grammar, coverage: FunctionCoverageMap, origin, original_grammar=None, original_coverage: Optional[FunctionCoverageMap]=None):
    global NEXT_GRAMMAR_ID
    val = NEXT_GRAMMAR_ID
    NEXT_GRAMMAR_ID += 1
    os.makedirs(stats_dir() / 'grammars', exist_ok=True)
    grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
    base_suffix = f'{val}_{int(time.time())}'
    base_path = str(stats_dir() / 'grammars' / base_suffix)

    with open(base_path + '.py', 'w') as f:
        f.write(grammar)
    with open(base_path + '.cov.yaml', 'w') as f:
        yaml.safe_dump({
            key: [line.as_tuple() for line in lines] for key, lines in coverage.items()
        }, f)
    with open(base_path + '.reached.cov.yaml', 'w') as f:
        yaml.safe_dump({
            fun: {
                cov_line.line_number: cov_line.code
                for cov_line in cov
                if cov_line.count_covered
            }
            for fun, cov in coverage.items()
            }, f)
    with open(base_path + '.original.py', 'w') as f:
        f.write(original_grammar or '')
    with open(base_path + '.original.cov.yaml', 'w') as f:
        yaml.dump({
            key: [line.as_tuple() for line in lines] for key, lines in original_coverage.items()
        }, f)
    with open(base_path + '.reached.original.cov.yaml', 'w') as f:
        yaml.dump({
            fun: {
                cov_line.line_number: cov_line.code
                for cov_line in cov
                if cov_line.count_covered
            }
            for fun, cov in (original_coverage or {}).items()
            }, f)
    with open(base_path + '.origin.yaml', 'w') as f:
        yaml.dump(origin, f)
    target_func_cov_path = stats_dir() / "grammars" / "target_func_cov.json"
    with open(target_func_cov_path, "r") as f:
        target_functions = json.load(f)
    with open(target_func_cov_path, "w") as f:
        global LIST_OF_FUNCTIONS
        target_functions.append({
            "grammar_file": str(stats_dir() / f"grammars/{base_suffix}.py"),
            "functions": {}
        })
        for func in (LIST_OF_FUNCTIONS or []):
            covered_lines = coverage.get(func, [])
            target_functions[val]["functions"][func] = sum([1 for cov_line in covered_lines if cov_line.count_covered and cov_line.count_covered > 0])

            if len(covered_lines) > 0:
                target_functions[val]["functions"][func] /= len(covered_lines)
            else:
                target_functions[val]["functions"][func] = 0.0

            if target_functions[val]["functions"][func] > 0:
                if val == 0 or target_functions[val - 1]["functions"][func] == 0:
                    print(f"Function {func} achieved coverage!")
        json.dump(target_functions, f)
    return val

def log_event(type, data):
    ''' Log an event to the log file
    :param str type: the type of the event
    :param str data: the data of the event
    '''
    # from pprint import pprint; pprint(f"Data to be logged \n {data}")
    if stats_dir():
        os.makedirs(stats_dir(), exist_ok=True)
        with open(str(stats_dir() / str(int(time.time()))) + '_' + type + '.log', 'w') as f:
            yaml.safe_dump({"event": type, "data": data, "time": time.time()}, f)

def increment_input_generated_total(increment: int = 1):
    global INPUT_GENERATED_TOTAL
    INPUT_GENERATED_TOTAL += increment

def set_target_functions(functions: list[str]):
    global LIST_OF_FUNCTIONS
    LIST_OF_FUNCTIONS = functions

def adjust_improvement_strategies(strategies: list[str]):
    global IMPROVEMENT_STRATEGIES
    IMPROVEMENT_STRATEGIES = strategies

@contextmanager
def launch_coverage_tracer():
    global COVERAGE_TRACER
    parser = {
        LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
    }[TARGET_PROJECT.project_metadata.language]()
    with Tracer(TARGET_PROJECT.project_path, CP_HARNESS_NAME, parser=parser, aggregate=True) as tracer:
        COVERAGE_TRACER = tracer
        yield

def get_fuzzer_sync_dirs():
    return FUZZER_SYNC_DIRS

def set_directories():
    replica_id = os.environ.get('REPLICA_ID')
    if replica_id is None: 
        replica_id = 0
    task_name = os.environ.get('TASK_NAME', '')
    job_id = os.environ.get('JOB_ID', '')
    project_id = PROJECT_HARNESS_METADATA['project_id']
    replica_id = os.environ.get('REPLICA_ID', '0')

    for harness_info_id, harness_info in HARNESS_INFO_DICT.items():
        project_name = PROJECT_HARNESS_METADATA['project_name']
        cp_harness_name = harness_info.cp_harness_name

        # Generate the paths according to the patterns
        # afl_sync_path = pathlib.Path(f"/shared/fuzzer_sync/{task_name}-{job_id}-{project_name}-{replica_id}/sync-grammar-guy/queue")
        # fuzzer_sync_dir = pathlib.Path(f"/shared/fuzzer_sync/{task_name}-{job_id}-{project_name}/sync-grammar-guy-{replica_id}")
        
        fuzzer_sync_dir = pathlib.Path(f"/shared/fuzzer_sync/{project_name}-{cp_harness_name}-{harness_info_id}/sync-{task_name.replace('_', '-')}-{replica_id}")
        
        # Create directories if they don't exist
        os.makedirs(fuzzer_sync_dir / 'queue', exist_ok=True) # create the queue too while we're at it
        FUZZER_SYNC_DIRS.append(fuzzer_sync_dir) 