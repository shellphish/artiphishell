

import logging
import time

from neomodel import db
from typing import List

from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.sarif import SARIFreport
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY
from analysis_graph.api import add_sarif_report

logger = logging.getLogger("discoveryguy.analysis_graph_api")
logger.setLevel(logging.INFO)

class AnalysisGraphAPI:
    def __init__(self):
        pass

    def upload_bypass_to_analysis_graph(self, identifier, patch_id):
        logger.info(f"Uploading bypass to analysis graph")
        # Connect the HarnessInputNode to the GeneratedPatch with id = patch_id
        query = """
        MATCH (input:HarnessInputNode) WHERE input.identifier CONTAINS $harness_input_id
        MATCH (patch:GeneratedPatch) WHERE patch.patch_key = $patch_id
        CREATE (input)-[:BYPASS]->(patch)
        RETURN input, patch
        """
        params = {
            "harness_input_id": identifier,
            "patch_id": patch_id,
        }
        results, columns = db.cypher_query(query=query, params=params, resolve_objects=True)

        return results

    def link_seed_to_sarif(self, seed_id, sarif_id, sarif_resolver):

        # NOTE: check if the sarif report exists (sarifguy should have uploaded it at this point)
        sarif_node = SARIFreport.get_node_or_none(sarif_uid=sarif_id)

        if sarif_node == None:
            # For some reasons the sarifguy did not upload the sarif report, we are gonna do it...
            covered_functions_keys = set()
            for sarif_result in sarif_resolver.get_results():
                for loc in sarif_result.locations:
                    covered_functions_keys.add(loc.keyindex)
                for codeflow in sarif_result.codeflows:
                    for loc in codeflow.locations:
                        covered_functions_keys.add(loc.keyindex)

            try:
                add_sarif_report(
                    sarif_uid=str(sarif_id),
                    sarif_type="injected",
                    sarif_path=sarif_resolver.sarif_path,
                    covered_functions_keys=covered_functions_keys
                )
            except Exception as e:
                logger.error(f"🙊 Failed to add sarif report {sarif_id} to analysis graph: {e}")
                return None

        # NOTE: now we connect the crashing input to the sarif report
        query = """
        MATCH (input:HarnessInputNode) WHERE input.identifier CONTAINS $seed_id
        MATCH (sarif:SARIFreport) WHERE sarif.sarif_uid = $sarif_id
        CREATE (sarif)-[:CRASHED_BY]->(input)
        RETURN input, sarif
        """
        params = {
            "seed_id": seed_id,
            "sarif_id": str(sarif_id),
        }
        results, columns = db.cypher_query(query=query, params=params, resolve_objects=True)

        return results

    def get_crashing_input_for_sink(self, sink_funcname):
        query = f"""
        MATCH (f:CFGFunction) WHERE f.identifier CONTAINS $sink_funcname
        MATCH (input:HarnessInputNode)-[:COVERS]->(f)
        WHERE input.crashing = true
        RETURN input
        """

        params = {
            "sink_funcname": sink_funcname,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)

        return results


    def is_sink_crashed_already(self, sink_funcname):

        query = f"""
        MATCH (n:OrganizerDedupInfoNode)
        WHERE n.crash_state CONTAINS $sink_funcname
        RETURN n LIMIT 1
        """

        params = {
            "sink_funcname": sink_funcname,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)

        return results

    def get_benign_input_for_function(self, sink_funcname):

        query = f"""
        MATCH (f:CFGFunction) WHERE f.identifier CONTAINS $sink_funcname
        MATCH (input:HarnessInputNode)-[:COVERS]->(f)
        WHERE input.crashing = false
        RETURN input
        """

        params = {
            "sink_funcname": sink_funcname,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)

        return results

    def get_paths_from_harness_to_sink(self, harness_name, sink_funcindex):
        # Checks if there exists a patch from source to sink
        #print(f"Checking if there exists a path from an harness to {sink_funcindex}")

        # NOTE: we are looking for path that have a MAX of 10 hops
        # NOTE: we are limiting this search to ONLY 3 paths
        query = f"""
            MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $harness_name
            WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
            WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..10]->(end)
            RETURN DISTINCT p LIMIT 3
        """
        params = {
            "harness_name": harness_name,
            "sink_funcindex": sink_funcindex,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)

        return results

    def check_exists_path_to_harness(self, harness_prefix, sink_funcindex):
        # Checks if there exists a patch from source to sink
        #print(f"Checking if there exists a path from an harness to {sink_funcindex}")

        # NOTE: we are looking for path that have a MAX of 10 hops
        # NOTE: we are limiting this search to ONLY 3 paths
        # FIXME: We need a better way to identify harnesses node!
        query = f"""
            MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $harness_prefix
            AND NOT start.identifier  CONTAINS "LLVMFuzzerInitialize"
            WITH start MATCH (end:CFGFunction)
            WHERE end.identifier = $sink_funcindex
            WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..10]->(end)
            RETURN DISTINCT start
        """
        params = {
            "harness_prefix": harness_prefix,
            "sink_funcindex": sink_funcindex,
        }
        results, columns = db.cypher_query(query=query, params=params)

        return results

    def get_coverage_feedback(self, coverage:FileCoverageMap, harness_id:FUNCTION_INDEX_KEY, sink_id:FUNCTION_INDEX_KEY, seen: List[FUNCTION_INDEX_KEY], num_paths:int=10):
        query = """CALL () {
            WITH $harness_id AS harness_id
            MATCH (s:CFGFunction)
            WHERE s.identifier = harness_id
            RETURN s
            LIMIT 1
            }

            CALL () {
            WITH $sink_id as sink_id
            MATCH (e:CFGFunction)
            WHERE e.identifier = sink_id
            RETURN e
            LIMIT 1
            }

            CALL apoc.path.expandConfig(s, {
            uniqueness: "NODE_GLOBAL",
            labelFilter: "-ExcludedLabel", // optional
            filterStartNode: true,
            endNodes: []
            }) YIELD path AS p1

            WITH s, e, p1, last(nodes(p1)) AS m, $seen as seen
            WHERE m.identifier IN seen
            MATCH (m:CFGFunction)-[]->(n:CFGFunction)
            WHERE NONE(id IN seen WHERE n.identifier = id)
            CALL apoc.path.expandConfig(n, {
            uniqueness: "NODE_GLOBAL",
            endNodes: [e],
            filterStartNode: true
            }) YIELD path AS p2

            LIMIT $num_paths
            RETURN DISTINCT m, n;
        """

        params = {
            "harness_id": harness_id,
            "sink_id": sink_id,
            "seen": seen,
            "num_paths" : num_paths
        }

        results, columns = db.cypher_query(query=query, params=params)

        return [(CFGFunction.inflate(row[0]), CFGFunction.inflate(row[1])) for row in results]

    def callers_of_sink(self, sink_funcindex, max_length=3):
        # Checks if there exists a patch from source to sink
        #print(f"Checking if there exists a path from an harness to {sink_funcindex}")
        query = f"""
            MATCH (start:CFGFunction) WHERE start.identifier CONTAINS "bld"
            WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
            WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..{max_length}]->(end)
            RETURN DISTINCT start
        """
        params = {
            "sink_funcindex": sink_funcindex,
        }

        results, columns = db.cypher_query(query=query, params=params)

        return results

    def get_global_variable_usage(self, filename):
        query = f"""
            MATCH (f:CFGGlobalVariable) WHERE f.identifier CONTAINS $filename
            RETURN f

        """
        params = {
            "filename": filename,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects=True)

        return results

    def get_patch_info(self, patch_key: str):
        query = f"""
        MATCH (p:GeneratedPatch) WHERE p.patch_key = $patch_key
        RETURN p
        """

        params = {
            "patch_key": patch_key,
        }

        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)
        if not results:
            raise ValueError(f"No patch found with key: {patch_key}")
        # If the structure changes then we need to update this
        patch = results[0][0].diff
        return patch

    def get_pois_data(self, poi_key: str):
        query = f"""
        MATCH (p:PoVReportNode) WHERE p.key = $poi_key
        RETURN p
        """

        params = {
            "poi_key": poi_key,
        }
        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)
        if not results:
            raise ValueError(f"No POI found with key: {poi_key}")

        PoVReportNodeData = results[0][0].content
        return PoVReportNodeData

    def get_crashing_input(self, patch_id):
        query = f"""
        match (p:GeneratedPatch) --> (r:PoVReportNode) where p.patch_key = $patch_id
        match (r) --> (i:HarnessInputNode) where i.crashing = true
        return i"""
        params = {
            "patch_id": patch_id,
        }
        results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)
        if not results:
            raise ValueError(f"No crashing input found for patch: {patch_id}")
        # If the structure changes then we need to update this
        crashing_input = results[0][0].content_escaped
        return crashing_input