from typing import Optional
import logging
import random
import time

from grammar_guy.common.utils import get_uncovered_functions_called_in_function, is_improvable_function, get_covered_uncovered_lines, is_covered_function
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FUNCTION_INDEX_KEY
import grammar_guy.common.config as config

log = logging.getLogger("grammar_guy")

def find_random_reachable_function_to_improve(coverage_by_function: FunctionCoverageMap) -> Optional[FUNCTION_INDEX_KEY]:
    improvable_functions = [
    f for f in config.LIST_OF_FUNCTIONS
    if f in coverage_by_function and is_improvable_function(*get_covered_uncovered_lines(coverage_by_function[f]))
    ]
    if len(improvable_functions) == 0:
        return None
    # harness and function tuple
    return random.choice(improvable_functions)

def find_random_unhit_function_to_improve(coverage_by_function: FunctionCoverageMap) -> Optional[FUNCTION_INDEX_KEY]: 
    # Use harness and target function
    improvable_functions = [
        f for f in config.LIST_OF_FUNCTIONS
        if f in coverage_by_function and not is_covered_function(coverage_by_function[f])
    ]
    if len(improvable_functions) == 0:
        return None
    # harness and function tuple
    return random.choice(improvable_functions)

def find_function_pairs_to_improve(coverage_by_function: FunctionCoverageMap) -> Optional[list[tuple[FUNCTION_INDEX_KEY, FUNCTION_INDEX_KEY]]]:
    ''' Gets coverage for all functions. Selects a function to improve based on the list of functions and non-reached coverage
    :param dict coverage_by_function: the coverage dictionary for all functions
    :return: a list of tuples of all possible (function_to_improve_from, function_to_improve_towards)
    '''
    log.info("Finding function pairs to improve")
    # Start time 
    start_time = time.time()
    improvable_functions = [
        f for f in config.LIST_OF_FUNCTIONS
        if f in coverage_by_function and is_improvable_function(*get_covered_uncovered_lines(coverage_by_function[f]))
    ]
    time_to_find_improvable_functions = time.time() - start_time
    log.info('Time to find improvable functions: {:.2f} seconds'.format(time_to_find_improvable_functions))
    call_pairs_for_improvement = []
    start_time = time.time()
    for fun in improvable_functions:
        uncovered_callable_functions = get_uncovered_functions_called_in_function(coverage_by_function, fun)
        for uncovered_function in uncovered_callable_functions:    
            call_pairs_for_improvement.append((fun, uncovered_function))
    time_to_find_call_pairs = time.time() - start_time
    log.info('Time to find call pairs for improvement: {:.2f} seconds'.format(time_to_find_call_pairs))
    if len(call_pairs_for_improvement) == 0:
        return None
    
    return call_pairs_for_improvement

def find_function_pairs_codeflow(codeflow_locations_deduped: list[str]) -> Optional[list[tuple[FUNCTION_INDEX_KEY, FUNCTION_INDEX_KEY]]]:
    
    pass