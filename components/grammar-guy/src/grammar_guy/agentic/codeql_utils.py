import time
import traceback
from typing import Dict, List, Tuple
from analysis_graph import CFGFunction, db
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from grammar_guy.agentic.globals import (
    REACHING_FUNCTION_GRAMMARS
)

LAST_INDIRECT_CALL_TABLE_QUERY_TIME = 0
LAST_INDIRECT_CALL_TABLE_QUERY_RESULT = None
def get_indirect_call_table() -> List[Tuple[str, List[FUNCTION_INDEX_KEY]]]:
    global LAST_INDIRECT_CALL_TABLE_QUERY_TIME
    global LAST_INDIRECT_CALL_TABLE_QUERY_RESULT

    cur_time = time.time()
    if cur_time - LAST_INDIRECT_CALL_TABLE_QUERY_TIME < 10:
        return LAST_INDIRECT_CALL_TABLE_QUERY_RESULT
    LAST_INDIRECT_CALL_TABLE_QUERY_TIME = cur_time
    try:
        LAST_INDIRECT_CALL_TABLE_QUERY_RESULT = list(db.cypher_query('MATCH (a)-[:TAKES_POINTER_OF]->(x: CFGFunction) RETURN a.identifier, COLLECT(x.identifier)'))
    except:
        traceback.print_exc()
    return LAST_INDIRECT_CALL_TABLE_QUERY_RESULT[0]

def get_indirect_call_targets_within_reach(filter_func=None) -> Dict[str, Tuple[List[FUNCTION_INDEX_KEY], List[FUNCTION_INDEX_KEY]]]:
    # this returns for each global reference identifier that has potential results available a list of
    # functions that were already reached and a list of functions that wasn't reached yet
    if (indirect_call_table := get_indirect_call_table()) is None:
        return []

    x = {}
    for reference_ident, functions in indirect_call_table:
        reached, not_reached = [], []
        for func in functions:
            (reached if func in REACHING_FUNCTION_GRAMMARS else not_reached).append(func)
        if filter_func and not filter_func(reference_ident, reached, not_reached):
            continue
        x[reference_ident] = (reached, not_reached)
    return x
