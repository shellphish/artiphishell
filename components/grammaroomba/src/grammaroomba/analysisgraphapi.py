# Standard library imports 
import time
import logging
from datetime import datetime
from typing import List, Tuple
from neomodel import db

# Local imports 

# Shellphish imports
from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.grammars import Grammar
from analysis_graph.models.harness_inputs import HarnessInputNode
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY

log = logging.getLogger("grammaroomba.analysis_graph_api")
log.setLevel(logging.INFO)


def get_covered_function_information(harness_name: str) -> List[Tuple[CFGFunction, HarnessInputNode, Grammar]]:
    query = """
    MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f:CFGFunction)<-[:COVERS]-(g:Grammar)

    // Order rows
    WITH h, f, g
    ORDER BY h.first_discovered_timestamp DESC

    // Deduplicate
    WITH f,
        collect(h)[0] AS h,
        collect(g)[0] AS g
    RETURN f, h, g
    LIMIT 1000
    """
    params = {"harness_name": harness_name}
    log.info(f"Executing query to get covered function information for harness: {harness_name}")
    log.info(f"Query: {query} with params: {params}")
    try:
        results, columns = db.cypher_query(query, params, resolve_objects=True)
    except Exception as e:
        log.error(f"Error executing query: {e}")
        return []
    return results

def get_cov_function_delta_information(cp_harness_name: str, timestamp_last_entry: datetime) -> List[Tuple[CFGFunction, HarnessInputNode, Grammar]]:
    assert len(cp_harness_name) > 0, "cp_harness_name must not be empty"

    if timestamp_last_entry is None:
        return get_covered_function_information(cp_harness_name) 
        
    query = """ 
    MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f:CFGFunction)<-[:COVERS]-(g:Grammar)
    WHERE h.first_discovered_timestamp > $timestamp_last_entry

    // Order rows
    WITH h, f, g
    ORDER BY h.first_discovered_timestamp DESC

    // Deduplicate
    WITH f,
        collect(h)[0] AS h,
        collect(g)[0] AS g
    RETURN f, h, g
    LIMIT 1000
    """
    params = {
        "harness_name": cp_harness_name,
        "timestamp_last_entry": timestamp_last_entry.isoformat()
    }
    log.info(f"Executing query to get covered function information for harness: {cp_harness_name}")
    log.info(f"Query: {query} with params: {params}")
    try:
        results, columns = db.cypher_query(query, params, resolve_objects=True)
    except Exception as e:
        log.error(f"Error executing query: {e}")
        return []
    return results