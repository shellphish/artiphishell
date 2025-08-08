import argparse
import pathlib
import os

FUNCTIONS_INDEX_PATH= None
JSONS_DIR_PATH= None
HARNESS_INFO_PATH= None
TARGET_SOURCE_PATH=None
CRASH_REPORT_PATH=None
INPUT_FINAL_DESTINATION=None
LIST_OF_FUNCTIONS = None
ITERATIONS= None
MODEL= None
NUM_INPUT= None
GG_SOURCE= None
STATS_DIR = None

def parse_config_from_args():
    global CRASH_REPORT_PATH    
    global FUNCTIONS_INDEX_PATH
    global JSONS_DIR_PATH
    global HARNESS_INFO_PATH
    global ITERATIONS
    global MODEL
    global NUM_INPUT
    global GG_SOURCE
    global INPUT_FINAL_DESTINATION
    global LIST_OF_FUNCTIONS
    global STATS_DIR
    
    parser = argparse.ArgumentParser( prog='SPEARFUZZ', description='Fuzzes the thing', epilog='hehe fuzzing go sprrrrrrr')
    parser.add_argument('-i', '--iterations', help='The number of iterations to improve the grammar', default=1)
    parser.add_argument('-n', '--num_input', help='The number of inputs created for each iteration of grammar improvement', default=300)
    parser.add_argument('-m', '--model', help='The model to use', default='gpt-3.5-turbo') # TODO change me back when done testing
    
    # Path arguments
    parser.add_argument('-t', '--target', help='The target source path', required=True)
    parser.add_argument('-b', '--harness_info', help='YAML file containing information on harness', required=True)
    parser.add_argument('-idx', '--function_index_path', help='Full function index file path', required=True)
    parser.add_argument('-cr', '--crash_report_path', help='The path to the crash report', default="nah boi i aint got no crash report")
    parser.add_argument('-jd', '--json_dir_path', help='The path to the functions JSON directory', required=True)
    parser.add_argument('-src', '--gg_source', help='The path to the grammar guy source', default="/shellphish/grammar_guy/src/")
    parser.add_argument('-ifd', '--input_final_destination', help='The path to the final destination of the inputs', required=True)
    parser.add_argument('-f', '--functions', help='The list of functions (a json file)', required=True)
    parser.add_argument("-s", "--stats-dir", help="The directory to store the stats")
    
    args = parser.parse_args()
    set_target_source_path(args.target)
    FUNCTIONS_INDEX_PATH = pathlib.Path(args.function_index_path)
    JSONS_DIR_PATH = pathlib.Path(args.json_dir_path)
    HARNESS_INFO_PATH = pathlib.Path(args.harness_info)
    CRASH_REPORT_PATH = pathlib.Path(args.crash_report_path)
    INPUT_FINAL_DESTINATION = pathlib.Path(args.input_final_destination)
    LIST_OF_FUNCTIONS = pathlib.Path(args.functions)
    STATS_DIR = pathlib.Path(args.stats_dir)
    print(f"STATS_DIR: {STATS_DIR}")

    ITERATIONS = args.iterations
    MODEL = args.model
    NUM_INPUT = args.num_input
    GG_SOURCE = pathlib.Path(args.gg_source)
    
    # asserts for all the paths above
    assert FUNCTIONS_INDEX_PATH.exists(), f"Function index file does not exist at {FUNCTIONS_INDEX_PATH}"
    assert JSONS_DIR_PATH.exists(), f"JSON directory does not exist at {JSONS_DIR_PATH}"
    assert HARNESS_INFO_PATH.exists(), f"YAML file containing information on harness does not exist at {HARNESS_INFO_PATH}"
    assert TARGET_SOURCE_PATH.exists(), f"Target source path does not exist at {TARGET_SOURCE_PATH}"
    # assert CRASH_REPORT_PATH.exists(), f"Crash report path does not exist at {CRASH_REPORT_PATH}"
    assert GG_SOURCE.exists(), f"Grammar guy source does not exist at {GG_SOURCE}"
    
def set_allowlist(functions_list):
    
    # check if allowlist exists, remove it and create new empty file 
    if allowlist_path().exists():
        os.remove(allowlist_path())
        open(str(allowlist_path()), 'w').close()

    with open(str(allowlist_path()), 'a') as allowlist:
        for i in functions_list:
            # remove old allowlist
            allowlist.write(f"allowlist_fun:{i}" + '\n')
                
def set_target_source_path(path):
    global TARGET_SOURCE_PATH
    TARGET_SOURCE_PATH = pathlib.Path(path)
    os.makedirs(TARGET_SOURCE_PATH / 'work' / 'grammar', exist_ok=True)
    os.makedirs(TARGET_SOURCE_PATH / 'work' / 'coverage', exist_ok=True)
    os.makedirs(TARGET_SOURCE_PATH / 'work' / 'inputs', exist_ok=True)


def generated_inputs_path():
    return TARGET_SOURCE_PATH / 'work' / 'inputs'

def functions_index_path():
    return FUNCTIONS_INDEX_PATH

def target_source_path(): 
    return TARGET_SOURCE_PATH

def jsons_dir_path():
    return JSONS_DIR_PATH

def harness_info_path(): 
    return HARNESS_INFO_PATH

def crash_report_path():
    return CRASH_REPORT_PATH

def coverage_path():
    return TARGET_SOURCE_PATH / 'work' / 'coverage'

def allowlist_path():
    return TARGET_SOURCE_PATH / 'work' / 'allowlist.txt'

def grammar_path(): 
    return TARGET_SOURCE_PATH / 'work' / 'grammar' # / "spearfuzz.g4"

def iterations(): 
    return ITERATIONS

def gg_source():
    return GG_SOURCE

def num_input(): 
    return NUM_INPUT

def model():
    return MODEL

def input_final_destination():
    return INPUT_FINAL_DESTINATION

def input_list_of_functions(): 
    return LIST_OF_FUNCTIONS

def stats_dir():
    return STATS_DIR