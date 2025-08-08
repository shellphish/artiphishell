# Standard library imports
import os
import time
import hashlib
import logging
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

# Local imports
from grammaroomba.ranker import FunctionRanker, FunctionMetrics

# Shellphish imports
from agentlib import tools
from coveragelib.trace import Tracer
from permanence.client import PermanenceClient
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from grammaroomba.grammars import NautilusPythonGrammar
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.function_resolver import FunctionResolver, FUNCTION_INDEX_KEY, RemoteFunctionResolver

log = logging.getLogger("grammaroomba.globals")
@dataclass
class Globals:
    """
    Container for fuzzer-wide state.
    """
    already_imported_functions:     List[str] = field(default_factory=list)

    seed_to_function_mapping:       Dict[Path, str] = field(default_factory=dict)
    grammar_to_function_mapping:    Dict[str, str]  = field(default_factory=dict)
    #
    fuzzer_name:                    str = 'grammaroomba'
    #
    parser:                         Any                                                     = None
    target:                         InstrumentedOssFuzzProject | None                       = None
    tracer:                         Any                                                     = None
    losan_target:                   InstrumentedOssFuzzProject | None                       = None
    function_resolver:              RemoteFunctionResolver | None                           = None
    harness_function_index_key:     str                                                     = ''
    harness_source_code:            str                                                     = ''
    project_metadata_file:          Path                                                    = Path()
    project_metadata:               AugmentedProjectMetadata | None                         = None
    fuzzer_sync_dir:                Path                                                    = Path()
    commit_functions_index:         Path                                                    = Path()
    permanence_client:              PermanenceClient | None                                 = None
    function_discovery_timestamps:  Dict[FUNCTION_INDEX_KEY, float]                         = field(default_factory=dict)
    file_discovery_timestamps:      Dict[Path, float]                                       = field(default_factory=dict)
    grammar_function_coverages:     Dict[NautilusPythonGrammar, FunctionCoverageMap]        = field(default_factory=dict)
    grammar_file_coverages:         Dict[NautilusPythonGrammar, FileCoverageMap]            = field(default_factory=dict)
    reaching_function_grammars:     Dict[FUNCTION_INDEX_KEY, List[NautilusPythonGrammar]]   = field(default_factory=dict)
    reaching_file_grammars:         Dict[str, List[NautilusPythonGrammar]]                  = field(default_factory=dict)
    current_function_meta:          Any                                                     = None
    memories:                       List[str]                                               = field(default_factory=list)
    #
    project_harness_metadata:       Dict                                                    = field(default_factory=dict)
    project_harness_metadata_id:    str                                                     = ''
    target_shared_dir:              Path                                                    = Path()
    target_split_metadata:          Dict                                                    = field(default_factory=dict)
    cp_harness_name:                str                                                     = ''
    harness_info_dict:              Dict[str, HarnessInfo]                                  = field(default_factory=dict)
    harness_info_files:             List                                                    = field(default_factory=list)
    fuzzer_sync_dirs:               List                                                    = field(default_factory=list)
    full_index_file:                str | None                                              = ''
    function_ranking:               Dict[FUNCTION_INDEX_KEY, FunctionMetrics]               = field(default_factory=dict)
    diff_functions:                 List[FUNCTION_INDEX_KEY]                                = field(default_factory=list)
    function_ranker:                FunctionRanker                                          = None
    seen_keys:                      Set[FUNCTION_INDEX_KEY]                                 = field(default_factory=set)

# one global instance that other modules can import
GLOBALS = Globals()

def save_new_fuzzer_inputs(grammar_type: str, grammar: str, seeds: List[Path], newly_reached_files: List[str], newly_reached_functions: List[FUNCTION_INDEX_KEY], **kwargs) -> None:
    """
    Save new fuzzer inputs to the fuzzer sync directory. The inputs are named based on the grammar and the seed name."
    These inputs are saved because they first newly reached the given files and functions."
    """
    # same shirt here. match the given harness infos for the cp_harness_name given from the pipeline and create fuzzer sync dir global list. When storing, iterate over all
    # items in fuzzer_sync_dir list
    if (pc := GLOBALS.permanence_client) is not None and (cov_tracer := GLOBALS.tracer) is not None:
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
    for sync_dir in GLOBALS.fuzzer_sync_dirs:
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
    for sync_dir in GLOBALS.fuzzer_sync_dirs:
        seed_sync_dir = sync_dir / 'queue' # Wrap this - do for each of the fuzzer synch dirs.
        seed_sync_dir.mkdir(parents=True, exist_ok=True)

        count_previous = len(os.listdir(seed_sync_dir))
        grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
        for i, seed in enumerate(seeds):
            seed_name = seed.name
            seed_path = seed_sync_dir / 'id:{:06d},grammar_src:{}-{},crashing:true'.format(count_previous, grammar_hash, seed_name)
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

def get_function_discovery_timestamp(function_key: FUNCTION_INDEX_KEY) -> Optional[float]:
    """
    Returns the timestamp of when a function was discovered.
    """
    return GLOBALS.function_discovery_timestamps.get(function_key, None)

def get_file_discovery_timestamp(file_key: Path) -> Optional[float]:
    """
    Returns the timestamp of when a file was discovered.
    """
    return GLOBALS.file_discovery_timestamps.get(file_key, None)

def register_grammar_coverage(grammar, file_coverage: FileCoverageMap, function_coverage: FunctionCoverageMap):
    GLOBALS.grammar_function_coverages[grammar] = function_coverage
    GLOBALS.grammar_file_coverages[grammar] = file_coverage
    newly_reached_functions = []
    newly_reached_files = []
    for function_key, lines in function_coverage.items():
        if any(l.count_covered and l.count_covered > 1 for l in lines):
            if not GLOBALS.reaching_function_grammars.get(function_key, None):
                log.info(f"NEW FUNCTION reached: {function_key}")
                newly_reached_functions.append(function_key)
            GLOBALS.reaching_function_grammars.setdefault(function_key, []).append(grammar)
            if function_key not in GLOBALS.function_discovery_timestamps:
                # If the function is not already in the dictionary, add it with the current time
                GLOBALS.function_discovery_timestamps[function_key] = time.time()
    for file_key, lines in file_coverage.items():
        if any(l.count_covered and l.count_covered > 1 for l in lines):
            if not GLOBALS.reaching_file_grammars.get(file_key, None): # FIXME??
                log.info(f"NEW FILE reached: {file_key}")
                newly_reached_files.append(file_key)
            GLOBALS.reaching_file_grammars.setdefault(file_key, []).append(grammar)
            if file_key not in GLOBALS.file_discovery_timestamps:
                # If the file is not already in the dictionary, add it with the current time
                GLOBALS.file_discovery_timestamps[file_key] = time.time()

    return newly_reached_functions, newly_reached_files

def wipe_memory():
    GLOBALS.memories = []