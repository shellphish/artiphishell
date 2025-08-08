
import os
import json
import hashlib

from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Optional
from analysis_graph.models.grammars import Grammar
from pydantic import BaseModel, Field
from neomodel import db
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.models.target import HarnessInfo
from analysis_graph.models.harness_inputs import HarnessInputNode, HarnessNode
from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.target_stats import CoveragePerformanceStats
from analysis_graph.models.coverage import CoveredFunctionLine

def register_relationships(all_calls_from_codeql, call_types, solver):

    for call in all_calls_from_codeql:
        entry = call["entry"]
        end = call["end"]
        entryId = call["entryId"]
        endId = call["endId"]
        properties = {
           "properties": call["property"]
        }
        entry_filename = endId.split(":")[1]
        end_filename = endId.split(":")[1]
        register_call_relationship(
            caller_file_name=entry, 
            callee_function_name=end, 
            caller_function_name=entry_filename,
            callee_file_name=end_filename,
            call_type=call_types, 
            solver=solver,
            properties=properties,
        )


def register_call_relationship(
        caller_function_name: str, 
        callee_function_name: str, 
        caller_file_name: str,
        callee_file_name: str, 
        call_type: str,
        solver: FunctionResolver,
        properties: Optional[Dict[str, str]] = None,
        caller_lineno: Optional[int] = None,
        callee_lineno: Optional[int] = None
        ):
    """
    Register a call relationship between two functions.
    """
    caller_identifier = get_identifier_from_funciton_resolver(caller_function_name, caller_file_name, solver, caller_lineno)
    callee_identifier = get_identifier_from_funciton_resolver(callee_function_name, callee_file_name, solver, callee_lineno)
    src = CFGFunction.get_or_create(dict(identifier=caller_identifier))[0]
    dst = CFGFunction.get_or_create(dict(identifier=callee_identifier))[0]

    if src and dst:
        src_property = getattr(src, call_type, None)
        relationship = src_property.is_connected(dst)
        if not relationship:
            src_property.connect(dst, properties)
    else:
        raise ValueError(f"src or dst does not exist {src} -> {dst}")


def get_identifier_from_funciton_resolver(function_name: str, function_filepath: str, solver: FunctionResolver, lineno: Optional[int] = None):
    ids_by_name = [i for i in solver.find_by_funcname(function_name)]
    ids_by_filename = [i for i in solver.find_by_filename(function_filepath)]

    intersection = list(set(ids_by_name) & set(ids_by_filename))
    if len(intersection) == 0:
        raise ValueError(f"Failed to find identifier for function {function_name} in {function_filepath} at line {lineno}")
    if len(intersection) == 1 or (not lineno):
        return intersection[0]

    for function_id in intersection:
        start_line, endline = solver.get_function_boundary(function_id)
        if start_line <= lineno <= endline:
            return function_id
    raise ValueError(f"Failed to find identifier for function {function_name} in {function_filepath} at line {lineno}")
