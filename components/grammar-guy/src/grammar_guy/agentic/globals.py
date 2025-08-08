


import hashlib
import logging
import os
from pathlib import Path
import tempfile
import time
from typing import Dict, List, Optional, Tuple
from analysis_graph.api.dynamic_coverage import register_grammar_function_coverage
from coveragelib.trace import Tracer
from shellphish_crs_utils.function_resolver import FunctionResolver, FUNCTION_INDEX_KEY
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from agentlib import tools
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from permanence.client import PermanenceClient

from grammar_guy.agentic.grammars import NautilusPythonGrammar

COVERAGE_TARGET: InstrumentedOssFuzzProject = None
LOSAN_TARGET: InstrumentedOssFuzzProject = None
COVERAGE_TRACER: Tracer = None
FUNCTION_RESOLVER: FunctionResolver = None
HARNESS_FUNCTION_INDEX: str = None
HARNESS_INFO: HarnessInfo = None
HARNESS_INFO_DICT: Dict[str, HarnessInfo] = {} # the harness info dict of harness infos in scope for the current harness
HARNESS_INFO_ID: str = None
FUZZER_SYNC_DIR : Path = None

# New vars
CP_HARNESS_NAME: str = None
HARNESS_INFOS: List[HarnessInfo] = []
FUZZER_SYNC_DIRS : List[Path] = []

log = logging.getLogger("grammar_guy.agentic.globals")

def set_cp_harness_name(harness_name: str) -> None:
    global CP_HARNESS_NAME
    CP_HARNESS_NAME = harness_name

def get_cp_harness_name() -> str:
    return CP_HARNESS_NAME

def set_fuzzer_sync_dirs(sync_dirs: List[Path]) -> None:
    global FUZZER_SYNC_DIRS
    for directory in sync_dirs:
        os.makedirs(directory, exist_ok=True)
        FUZZER_SYNC_DIRS.append(directory)

# Avoid double implementation for shared function between losan reproducer and agent explore
def get_fuzzer_sync_dirs() -> List[Path]:
    if FUZZER_SYNC_DIRS is None:
        return FUZZER_SYNC_DIR
    return FUZZER_SYNC_DIRS

def set_coverage_target(target: InstrumentedOssFuzzProject) -> None:
    global COVERAGE_TARGET
    COVERAGE_TARGET = target

def set_losan_target(target: InstrumentedOssFuzzProject) -> None:
    global LOSAN_TARGET
    LOSAN_TARGET = target

def set_coverage_tracer(tracer: Tracer) -> None:
    global COVERAGE_TRACER
    COVERAGE_TRACER = tracer

def set_function_resolver(resolver: FunctionResolver) -> None:
    global FUNCTION_RESOLVER
    FUNCTION_RESOLVER = resolver

def set_fuzzer_sync_dir(sync_dir: Path) -> None:
    global FUZZER_SYNC_DIR
    sync_dir.mkdir(parents=True, exist_ok=True)
    FUZZER_SYNC_DIR = sync_dir

def set_harness_index_key(key: str) -> None:
    global HARNESS_FUNCTION_INDEX
    HARNESS_FUNCTION_INDEX = key

def set_harness_info(info: HarnessInfo) -> None:
    global HARNESS_INFO
    HARNESS_INFO = info

def set_harness_info_dict(harness_info_dict: Dict[str, HarnessInfo]) -> None:
    """
    Set the harness info dict in the global HARNESS_INFO_DICT.
    This is used to access the harness info in the coverage tracer.
    """
    global HARNESS_INFO_DICT
    HARNESS_INFO_DICT = harness_info_dict

def set_harness_info_id(harness_info_id: str) -> None:
    """
    Set the harness info id in the global HARNESS_INFO.
    This is used to identify the harness in the coverage tracer.
    """
    global HARNESS_INFO_ID
    HARNESS_INFO_ID = harness_info_id

def get_function_resolver() -> FunctionResolver:
    return FUNCTION_RESOLVER

def get_coverage_tracer() -> Tracer:
    return COVERAGE_TRACER

def get_coverage_target() -> InstrumentedOssFuzzProject:
    return COVERAGE_TARGET

def get_losan_target() -> InstrumentedOssFuzzProject:
    return LOSAN_TARGET

def get_harness_index_key() -> str:
    return HARNESS_FUNCTION_INDEX

def get_harness_info() -> HarnessInfo:
    return HARNESS_INFO

def get_harness_info_dict() -> Dict[str, HarnessInfo]:
    """
    Returns a dictionary of harness info, where the key is the harness info id.
    This is used to access the harness info in the coverage tracer.
    """
    if not HARNESS_INFO_DICT:
        if HARNESS_INFO is not None and HARNESS_INFO_ID is not None:
            # If HARNESS_INFO_DICT is empty, we return a dict with the current harness info
            # This is a safety measure to ensure that we always have some harness info available.
            return {HARNESS_INFO_ID: HARNESS_INFO}
    return HARNESS_INFO_DICT or {}

def get_fuzzer_sync_dir() -> Path:
    return FUZZER_SYNC_DIR

global PERMANENCE_CLIENT
PERMANENCE_CLIENT = None
def get_permanence_client() -> Optional[PermanenceClient]:
    """
    Returns a PermanenceClient instance with the current function resolver and fuzzer sync directory.
    """
    global PERMANENCE_CLIENT
    func_resolver = get_function_resolver()
    if PERMANENCE_CLIENT is None and func_resolver is not None:
        PERMANENCE_CLIENT = PermanenceClient(
            function_resolver=func_resolver
        )

    return PERMANENCE_CLIENT

def save_grammar_coverage_to_analysis_graph(
        grammar_type: str,
        grammar: str,
        function_coverage: FunctionCoverageMap,
):

    try:
        harness_info_id_cur_first_hack, harness_info_cur_first_hack = next(iter(sorted(get_harness_info_dict().items())))
        register_grammar_function_coverage(
            harness_info_id_cur_first_hack,
            harness_info_cur_first_hack,
            grammar_type,
            grammar,
            function_coverage,
        )
    except Exception as e:
        log.error(f"Could not register grammar coverage: {e}", exc_info=True)
        if artiphishell_should_fail_on_error():
            raise


def save_new_fuzzer_inputs(grammar_type: str, grammar: str, seeds: List[Path], newly_reached_files: List[str], newly_reached_functions: List[FUNCTION_INDEX_KEY], **kwargs) -> None:
    """
    Save new fuzzer inputs to the fuzzer sync directory. The inputs are named based on the grammar and the seed name."
    These inputs are saved because they first newly reached the given files and functions."
    """

    if (pc := get_permanence_client()) is not None and (cov_tracer := get_coverage_tracer()) is not None:
        try:
            pc.seeds_reached(
                project_name=cov_tracer.instr_project.project_name,
                harness_name=cov_tracer.harness_name,
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
                project_name=cov_tracer.instr_project.project_name,
                harness_name=cov_tracer.harness_name,
                grammar_type=grammar_type,
                grammar=grammar,
                hit_functions=newly_reached_functions,
                hit_files=newly_reached_files,
                **kwargs,
            )
        except Exception as e:
            log.warning(f"Error while immortalizing function-reaching grammars: {e}")

        # Sync the seeds
    for sync_dir in get_fuzzer_sync_dirs():
        seed_sync_dir = sync_dir / 'queue'
        seed_sync_dir.mkdir(parents=True, exist_ok=True)
        count_previous = len(os.listdir(seed_sync_dir))
        grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
        for i, seed in enumerate(seeds):
            seed_name = seed.name
            seed_path = seed_sync_dir / 'id:{:06d},grammar_src:{}-{}'.format(count_previous, grammar_hash, seed_name)
            seed_path.write_bytes(seed.read_bytes())
            count_previous += 1

        # Sync the grammar
        grammar_sync_dir = sync_dir / '..' / 'sync-grammars' / grammar_type
        grammar_sync_dir.mkdir(parents=True, exist_ok=True)
        extension = '.py' if grammar_type == 'nautilus-python' else '.json'
        grammar_path = grammar_sync_dir / 'grammar_{}{}'.format(grammar_hash, extension)
        if not grammar_path.exists():
            grammar_path.write_text(grammar, encoding='utf-8')

def save_new_crashing_inputs(grammar: str, seeds: List[Path]) -> None:
    for sync_dir in get_fuzzer_sync_dirs():
        crash_sync_dir = sync_dir / 'queue'
        crash_sync_dir.mkdir(parents=True, exist_ok=True)

        count_previous = len(os.listdir(crash_sync_dir))
        grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
        for i, seed in enumerate(seeds):
            seed_name = seed.name
            seed_path = crash_sync_dir / 'id:{:06d},grammar_src:{}-{},crashing:true'.format(count_previous, grammar_hash, seed_name)
            seed_path.write_bytes(seed.read_bytes())
            count_previous += 1

        sync_dir_crashes = sync_dir / 'crashes'
        sync_dir_crashes.mkdir(parents=True, exist_ok=True)
        count_previous = len(os.listdir(sync_dir_crashes))
        for i, seed in enumerate(seeds):
            seed_name = seed.name
            seed_path = sync_dir_crashes / 'id:{:06d},grammar_src:{}-{},crashing:true'.format(count_previous, grammar_hash, seed_name)
            seed_path.write_bytes(seed.read_bytes())
            count_previous += 1

def save_new_losan_crashing_inputs(grammar: str, seeds: List[Path]) -> None:
    sync_dir = get_fuzzer_sync_dir() / 'queue'
    sync_dir.mkdir(parents=True, exist_ok=True)
    count_previous = len(os.listdir(sync_dir))
    grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
    for i, seed in enumerate(seeds):
        seed_name = seed.name
        seed_path = sync_dir / 'id:{:06d},grammar_src:{}-{},losan-crashing:true'.format(count_previous, grammar_hash, seed_name)
        seed_path.write_bytes(seed.read_bytes())
        count_previous += 1

    sync_dir_losan_crashes = get_fuzzer_sync_dir() / 'losan-crashes'
    sync_dir_losan_crashes.mkdir(parents=True, exist_ok=True)
    count_previous = len(os.listdir(sync_dir_losan_crashes))
    for i, seed in enumerate(seeds):
        seed_name = seed.name
        seed_path = sync_dir_losan_crashes / 'id:{:06d},grammar_src:{}-{},losan-crashing:true'.format(count_previous, grammar_hash, seed_name)
        seed_path.write_bytes(seed.read_bytes())
        count_previous += 1

FUNCTION_DISCOVERY_TIMESTAMPS: Dict[FUNCTION_INDEX_KEY, float] = {}
FILE_DISCOVERY_TIMESTAMPS: Dict[Path, float] = {}

def get_function_discovery_timestamp(function_key: FUNCTION_INDEX_KEY) -> Optional[float]:
    """
    Returns the timestamp of when a function was discovered.
    """
    return FUNCTION_DISCOVERY_TIMESTAMPS.get(function_key, None)
def get_file_discovery_timestamp(file_key: Path) -> Optional[float]:
    """
    Returns the timestamp of when a file was discovered.
    """
    return FILE_DISCOVERY_TIMESTAMPS.get(file_key, None)

GRAMMAR_FUNCTION_COVERAGES: Dict[NautilusPythonGrammar, FunctionCoverageMap] = {}
GRAMMAR_FILE_COVERAGES: Dict[NautilusPythonGrammar, FileCoverageMap] = {}
REACHING_FUNCTION_GRAMMARS: Dict[FUNCTION_INDEX_KEY, List[NautilusPythonGrammar]] = {} # maps each function to a grammar that reaches it
REACHING_FILE_GRAMMARS: Dict[str, List[NautilusPythonGrammar]] = {} # maps each file to a grammar that reaches it
def register_grammar_coverage(grammar, file_coverage: FileCoverageMap, function_coverage: FunctionCoverageMap):
    global REACHING_FUNCTION_GRAMMARS
    global REACHING_FILE_GRAMMARS
    global GRAMMAR_FUNCTION_COVERAGES
    global GRAMMAR_FILE_COVERAGES
    global FUNCTION_DISCOVERY_TIMESTAMPS
    global FILE_DISCOVERY_TIMESTAMPS
    GRAMMAR_FUNCTION_COVERAGES[grammar] = function_coverage
    GRAMMAR_FILE_COVERAGES[grammar] = file_coverage
    newly_reached_functions = []
    newly_reached_files = []
    for function_key, lines in function_coverage.items():
        if any(l.count_covered and l.count_covered > 1 for l in lines):
            if not REACHING_FUNCTION_GRAMMARS.get(function_key, None):
                log.info(f"NEW FUNCTION reached: {function_key}")
                newly_reached_functions.append(function_key)
            REACHING_FUNCTION_GRAMMARS.setdefault(function_key, []).append(grammar)
            if function_key not in FUNCTION_DISCOVERY_TIMESTAMPS:
                # If the function is not already in the dictionary, add it with the current time
                FUNCTION_DISCOVERY_TIMESTAMPS[function_key] = time.time()
    for file_key, lines in file_coverage.items():
        if any(l.count_covered and l.count_covered > 1 for l in lines):
            if not REACHING_FILE_GRAMMARS.get(file_key, None):
                log.info(f"NEW FILE reached: {file_key}")
                newly_reached_files.append(file_key)
            REACHING_FILE_GRAMMARS.setdefault(file_key, []).append(grammar)
            if file_key not in FILE_DISCOVERY_TIMESTAMPS:
                # If the file is not already in the dictionary, add it with the current time
                FILE_DISCOVERY_TIMESTAMPS[file_key] = time.time()

    return newly_reached_functions, newly_reached_files

def get_reaching_grammars_for_functions() -> Dict[FUNCTION_INDEX_KEY, List[NautilusPythonGrammar]]:
    """
    Returns a dictionary mapping each function to the grammars that reach it.
    """
    return REACHING_FUNCTION_GRAMMARS
def get_reaching_grammars_for_files() -> Dict[str, List[NautilusPythonGrammar]]:
    """
    Returns a dictionary mapping each file to the grammars that reach it.
    """
    return REACHING_FILE_GRAMMARS

MEMORIES = []
def wipe_memory():
    global MEMORIES
    MEMORIES = []