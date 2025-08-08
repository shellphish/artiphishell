import logging
from datetime import datetime
from typing import List, Tuple
from neomodel import db

from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.grammars import Grammar
from analysis_graph.models.harness_inputs import HarnessInputNode

log = logging.getLogger("grammaroomba.analysis_graph_api")
log.setLevel(logging.INFO)

def get_covered_function_information(harness_name: str) -> List[Tuple[CFGFunction, HarnessInputNode, Grammar]]:
    """
    Fetch up to 1000 distinct CFGFunction nodes covered by the given harness,
    returning for each the function, the most-recent HarnessInputNode, and
    one Grammar that covers it.
    """
    query = """
    CALL {
      MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f:CFGFunction)
      WITH f, max(h.first_discovered_timestamp) AS latest_ts
      ORDER BY latest_ts DESC
      LIMIT 1000
      RETURN f, latest_ts
    }
    MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f)
      WHERE h.first_discovered_timestamp = latest_ts
    WITH f, head(collect(h)) AS h
    OPTIONAL MATCH (g:Grammar)-[:COVERS]->(f)
    WITH f, h, head(collect(g)) AS g
    RETURN f, h, g
    """
    params = {"harness_name": harness_name}
    log.info(f"Querying most-recent coverage for harness={harness_name}")
    try:
        results, _ = db.cypher_query(query, params, resolve_objects=True)
        return results
    except Exception as e:
        log.error(f"Error executing optimized coverage query: {e}")
        return []


def get_cov_function_delta_information(harness_name: str,
                                       timestamp_last_entry: datetime
                                       ) -> List[Tuple[CFGFunction, HarnessInputNode, Grammar]]:
    """
    Same as get_covered_function_information, but only for coverages
    discovered after timestamp_last_entry. If timestamp_last_entry is None,
    falls back to full coverage fetch.
    """
    if timestamp_last_entry is None:
        return get_covered_function_information(harness_name)

    query = """
    CALL {
      MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f:CFGFunction)
      WHERE h.first_discovered_timestamp > datetime($timestamp_last_entry)
      WITH f, max(h.first_discovered_timestamp) AS latest_ts
      ORDER BY latest_ts DESC
      LIMIT 1000
      RETURN f, latest_ts
    }
    MATCH (h:HarnessInputNode {harness_name: $harness_name})-[:COVERS]->(f)
      WHERE h.first_discovered_timestamp = latest_ts
    WITH f, head(collect(h)) AS h
    OPTIONAL MATCH (g:Grammar)-[:COVERS]->(f)
    WITH f, h, head(collect(g)) AS g
    RETURN f, h, g
    """
    params = {
        "harness_name": harness_name,
        "timestamp_last_entry": timestamp_last_entry.isoformat()
    }
    log.info(f"Querying coverage delta for harness={harness_name} since {timestamp_last_entry.isoformat()}")
    try:
        results, _ = db.cypher_query(query, params, resolve_objects=True)
        return results
    except Exception as e:
        log.error(f"Error executing optimized delta coverage query: {e}")
        return []