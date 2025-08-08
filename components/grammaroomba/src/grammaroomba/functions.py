# Standard library imports
import re
import math
import logging
import itertools
import functools 
from dataclasses import dataclass, field 
from typing import List, Any, Tuple
from datetime import datetime, timezone
from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.grammars import Grammar
from analysis_graph.models.harness_inputs import HarnessInputNode

# Local imports
from grammaroomba.globals import GLOBALS
# from grammaroomba.analysisgraphapi import get_covered_function_information, get_cov_function_delta_information
from grammaroomba.graphapi_vibe import get_covered_function_information, get_cov_function_delta_information

# Shellphish imports
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY

log = logging.getLogger(__name__)

@functools.total_ordering
@dataclass
class FunctionMeta:
    # Basic info necessary to generate reports
    grammar:                        str                 = ''
    source_code:                    str                 = ''
    source_code_file:               str                 = ''
    mutated_grammar:                str                 = 'Not yet generated'
    seed_content:                   str                 = ''
    rank_score:                     float               = 0.0
    seed_discovered_timestamp:      Any                 = None
    total_lines:                    int                 = 0
    function_index_key:             FUNCTION_INDEX_KEY  = ''

    def __lt__(self, other):
        if not isinstance(other, FunctionMeta):
            return NotImplemented
        
        self_rank = get_key(self)
        other_rank = get_key(other)
        return self_rank < other_rank

class FunctionMetaStack: 
    def __init__(self):
        self.stack : List[FunctionMeta] = []
        self.max_stack_size: int = 100
        self.last_updated_time: datetime = None
        self.timestamp_last_entry: Any = None

    def push(self, function_meta: FunctionMeta):
        self.stack.append(function_meta)

    def pop(self) -> FunctionMeta:
        assert not self.is_empty(), "Attempted to pop from an empty FunctionMetaStack"
        return self.stack.pop()

    def update(self):
        if not hasattr(GLOBALS, "seen_keys") or not GLOBALS.seen_keys:
            GLOBALS.seen_keys = {meta.function_index_key for meta in self.stack}

        if self.last_updated_time is None:
            # Initial update
            self.last_updated_time = datetime.now(timezone.utc)
            try:
                cov_function_info = get_covered_function_information(GLOBALS.cp_harness_name)
            except Exception as e:
                log.error(f"Error fetching covered function information: {e}")
                cov_function_info = []

            for function, seed, grammar in cov_function_info:
                meta = self.entry_to_meta((function, seed, grammar))
                if len(meta.function_index_key) == 0:
                    log.warning("Encountered an entry with an empty function_index_key. Skipping this entry.")
                    continue
                if meta.function_index_key not in GLOBALS.seen_keys:
                    self.stack.append(meta)

            if cov_function_info:
                try:
                    self.timestamp_last_entry = max(
                        seed.first_discovered_timestamp
                        for _, seed, _ in cov_function_info
                    )
                except ValueError:
                    self.timestamp_last_entry = datetime.min.replace(tzinfo=timezone.utc)

        else:
            # Delta update
            self.last_updated_time = datetime.now(timezone.utc)
            try:
                cov_function_delta = get_cov_function_delta_information(
                    GLOBALS.cp_harness_name, self.timestamp_last_entry
                )
            except Exception as e:
                log.error(f"Error fetching coverage function delta information: {e}")
                cov_function_delta = []

            for function, seed, grammar in cov_function_delta:
                meta = self.entry_to_meta((function, seed, grammar))
                if len(meta.function_index_key) == 0:
                    log.warning("Encountered an entry with an empty function_index_key. Skipping this entry.")
                    continue
                if meta.function_index_key not in GLOBALS.seen_keys:
                    self.stack.append(meta)
                    GLOBALS.seen_keys.add(meta.function_index_key)

            if cov_function_delta:
                try:
                    new_max = max(
                        seed.first_discovered_timestamp
                        for _, seed, _ in cov_function_delta
                    )
                    # ensure we never move backwards in time
                    if self.timestamp_last_entry is None or new_max is None:
                        self.timestamp_last_entry = self.timestamp_last_entry or new_max
                    else:
                        self.timestamp_last_entry = max(self.timestamp_last_entry, new_max)
                except Exception as e:
                    log.error(f"Error updating timestamp_last_entry: {e}")
                    pass

        # rest of method unchanged: sort by timestamp, compute rank_score, trim, log, reorder
        self.stack.sort(key=lambda meta: (1 if meta.function_index_key in GLOBALS.diff_functions else 0, meta.seed_discovered_timestamp), reverse=True)
        for meta in self.stack:
            meta.rank_score = get_key(meta)[1]
        self.stack = self.stack[:self.max_stack_size]
        self.sort_stack_by_rank()
        log.info(f"Updated the FunctionMetaStack. Now contains {len(self.stack)} functions. Last updated at {self.last_updated_time.isoformat()}.")


    def entry_to_meta(self, entry: Tuple[CFGFunction, HarnessInputNode, Grammar]) -> FunctionMeta:
        try:
            meta = FunctionMeta()
            meta.function_index_key = entry[0].identifier
            meta.source_code = ''
            meta.total_lines = len(meta.source_code.splitlines())
            meta.seed_content = entry[1].content_escaped
            meta.seed_discovered_timestamp = entry[1].first_discovered_timestamp
            meta.grammar = entry[2].grammar
        except:
            return FunctionMeta()
        return meta
    
    def is_empty(self) -> bool:
        return len(self.stack) == 0
    
    def append(self, function_meta: FunctionMeta):
        assert isinstance(function_meta, FunctionMeta), "Only FunctionMeta instances can be appended to the stack"
        self.stack.append(function_meta)

    def sort_stack_by_rank(self):
        """
        Sorts the stack based on the rank of the functions.
        The rank is determined by the mapping in the GLOBALS.function_ranking() Dict[FUNCTION_INDEX_KEY, float].
        """
        self.stack = sorted(self.stack, key=get_key)

def get_key(p) -> Tuple[int, float]:
    try:
        return (1 if p.function_index_key in GLOBALS.diff_functions else 0, GLOBALS.function_ranking[p.function_index_key].complexity_score)
    except KeyError:
        log.warning("No rank entry for %s", p.function_index_key)
    except AttributeError:
        log.warning("%r lacks .function_index_key", p)
    except Exception:
        log.exception("Unexpected error while ranking %r", p)

    return (1 if p.function_index_key in GLOBALS.diff_functions else 0, float('inf'))