import time
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union, Tuple
from analysis_graph.models.grammars import Grammar
from pydantic import BaseModel, Field
from neomodel import db
from pathlib import Path

from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from analysis_graph.models.harness_inputs import HarnessNode
from analysis_graph.models.sarif import SARIFreport
from analysis_graph.models.cfg import CFGFunction

logger = logging.getLogger("analysis_graph")
logger.setLevel(logging.DEBUG)

def add_sarif_report(sarif_uid: str, sarif_type: str, sarif_path: Union[str, Path], covered_functions_keys: List[str]) -> SARIFreport:
    """
    Register a SARIF report in the database.
    :param sarif_uid: The SARIF report ID (as per pdt)
    :param sarif_type: This is either "injected" or "generated"
    :param covered_functions_keys: This is a list of funckeyindex that we are gonna convert into CFGFunction nodes
    """

    if isinstance(sarif_path, str):
        sarif_path = Path(sarif_path)
    
    # Get the content of the SARIF report
    try:
        with open(sarif_path, 'r', errors='ignore') as f:
            sarif_content = f.read()
    except Exception as e:
        print(f"Error reading SARIF file {sarif_path}: {e}")
        return None

    # Converts the functions index into CFGFunction nodes
    covered_functions_nodes = []
    for k in covered_functions_keys:
        try:
            with db.read_transaction as tx:
                covered_function = CFGFunction.nodes.get_or_none(identifier=k)
                if covered_function is None:
                    raise ValueError(f"CFGFunction with function_index_key {k} not found.")
                else:
                    logger.debug(f"CFGFunction with function_index_key {k} found.")
                    covered_functions_nodes.append(covered_function)
        except Exception as e:
            print(f"Error retrieving CFGFunction with function_index_key {k}: {e}")
            continue

    # Now let's create the SARIF report node with the connections 
    # to the CFGFunction nodes
    with db.write_transaction as tx:
        try:
            node_attrs = {
                'sarif_uid': sarif_uid,
                'sarif_type': sarif_type,
                'sarif_content': sarif_content,
            }
            sarif_report = SARIFreport.create_node(**node_attrs)
            sarif_report.save()

            for func_node in covered_functions_nodes:
                sarif_report.covered_functions.connect(func_node)

            sarif_report.save()
        except Exception as e:
            print(f"Error creating SARIF report node: {e}")
            return None

    assert(sarif_report is not None), f"Failed to create SARIF report node {sarif_report}"
    
    return sarif_report

def run_cypher_query(query: str, params: dict):
    attempts = 0
    for attempt in range(1, attempts + 1):
        try:
            results, columns = db.cypher_query(query=query, params=params)
            return results, columns
        except Exception as e:
            if attempt < attempts:
                logger.warning(f"❓ Error: {e}, retrying... (Attempt {attempt}/{attempts})")
                time.sleep(60)  # Wait for a minute before retrying
            else:
                logger.error(f"❌ Error: {e}, failed after {attempts} attempts.")
                return None, None
    return None, None

def get_sarif_id_from_vuln(vuln_identifier: str) -> Optional[str]:
    query = """
    MATCH (p:PoVReportNode)-[]-(h:HarnessInputNode)-[r]-(s:SARIFreport)
    WHERE p.key = $vuln_identifier
    RETURN s.sarif_uid
    """
    params = {
        "vuln_identifier": vuln_identifier,
    }

    results, columns = run_cypher_query(query=query, params=params)
    return results[0][0] if results else None

def get_sarif_id_from_patch(patch_identifier: str) -> Tuple[str, str] | Tuple[None, None]:
    query = """
    MATCH (patch:GeneratedPatch)-[r:MITIGATED_POV_REPORT]-(pov:PoVReportNode)-[]-(h:HarnessInputNode)-[]-(s:SARIFreport)
    WHERE patch.patch_key = $patch_identifier
    RETURN s.sarif_uid, pov.key
    LIMIT 1
    """
    params = {
        "patch_identifier": patch_identifier,
    }

    results, columns = run_cypher_query(query=query, params=params)
    return (results[0][0], results[0][1]) if results else (None, None)

def get_all_sarif_ids_and_pov_ids_from_project(project_id: str) -> Dict[str, str]:
    """
    Get all SARIF IDs and POV IDs from a project that are not mitigated by a patch.
    :param project_id: The project ID
    :return: A list of tuples of SARIF IDs and POV IDs
    """

    query = """
    MATCH (pov:PoVReportNode {pdt_project_id: $project_id})                           // candidate PoVs

    MATCH (pov)-[]-(:HarnessInputNode)-[]-(s:SARIFreport)
    WHERE NOT (pov)-[:MITIGATED_POV_REPORT]-(:GeneratedPatch)

    RETURN s.sarif_uid, pov.key
    """
    params = {
        "project_id": project_id,
    }

    results, columns = run_cypher_query(query=query, params=params)

    return {x[0]: x[1] for x in results} if results else {}



def get_pov_id_from_crash_id(crash_id: str) -> str:
    """
    Get the POV ID from the crash ID.
    :param crash_id: The crash ID
    :return: The POV ID
    """

    query = """
    MATCH (pov:PoVReportNode)-[]-(h:HarnessInputNode)
    WHERE h.pdt_id = $crash_id
    RETURN pov.key
    LIMIT 1
    """
    params = {
        "crash_id": crash_id,
    }

    results, columns = run_cypher_query(query=query, params=params)
    return results[0][0] if results else None