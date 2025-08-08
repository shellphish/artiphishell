

import logging

from neomodel import db
from typing import List, Optional

from analysis_graph.models.cfg import CFGFunction
from jinja2 import Template
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY


logger = logging.getLogger("scanguy.analysis_graph_api")
logger.setLevel(logging.INFO)

# ALL_SHORTEST_PATHS_TEMPLATE = """
#     MATCH (start:CFGFunction), (end: CFGFunction) 
#     WHERE start.identifier CONTAINS $source_identifier
#     AND end.identifier CONTAINS $target_identifier
#     WITH start, end 
#     MATCH path = allShortestPaths((start)-[:DIRECTLY_CALLS*1..{{ max_depth|default(10) }}]->(end)) 
#     RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
# """

SHORTEST_PATH_TEMPLATE = """
    MATCH (start:CFGFunction), (end: CFGFunction) 
    WHERE start.identifier CONTAINS $source_identifier
    AND end.identifier CONTAINS $target_identifier
    WITH start, end 
    MATCH path = shortestPath((start)-[:DIRECTLY_CALLS*1..{{ max_depth|default(10) }}]->(end)) 
    RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""

ALL_PATHS_ENDING_AT_TEMPLATE = """
MATCH (end:CFGFunction)
WHERE end.identifier CONTAINS $target_identifier
CALL apoc.path.expandConfig(end, {
    relationshipFilter: "<DIRECTLY_CALLS",
    minLevel: 1,
    maxLevel: {{ max_depth|default(10) }}
}) YIELD path
RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""


class AnalysisGraphAPI:
    def __init__(self):
        pass

    def parse_neo4j_path_query_result(self, results, limit=10):
        """
        Parse the result of a Neo4j path query.
        
        Args:
            result: The result from a Neo4j query execution.
            
        Returns:
            A list of paths with the identifiers
        """
        paths = set()
        for result in results:
            path = result.get("path")
            if not path:
                continue
            nodes = path.nodes
            path = tuple(node.get('identifier') for node in nodes)
            paths.add(path)
        path_list = [list(path) for path in paths]
        if len(path_list) > limit:
            path_list = path_list[:limit]
        return path_list

    def execute_neo4j_query_to_get_node_paths(
            self, 
            query: str,
            **kwargs) -> Optional[list]:
        """
        Execute a Neo4j query and return the results.
        
        Args:
            query: The Cypher query to execute.
        
        Returns:
            The results of the query execution.
        """
        results, columns = db.cypher_query(query=query, params=kwargs, resolve_objects = True)

        return results
    
    def get_paths_ending_at_query(self, end_node, max_length: int=10, limit: int=None) -> str:
        """
        Generate a Neo4j Cypher query to find paths ending at specified nodes.
        
        Args:
            end_nodes: List of node identifiers to match against the end of paths
            max_length: Maximum path length to search
            limit: Optional limit on number of results
        
        Returns:
            Rendered Cypher query string
        """
        cypher_template = Template(ALL_PATHS_ENDING_AT_TEMPLATE.strip())
        
        return cypher_template.render(
            target_identifer=end_node,
            max_length=max_length,
            limit=limit
        )
    
    def get_paths_ending_at(self, end_node, max_length: int=10, limit: int=5) -> Optional[list]:
        """
        Get all paths that end at specified nodes.
        """
        query = self.get_paths_ending_at_query(
            end_node=end_node,
            max_length=max_length,
            limit=limit
        )
        paths = self.execute_neo4j_query_to_get_node_paths(
            query, 
            target_identifier=end_node
        )
        reversed_paths = []
        for path in paths:
            reversed_paths.append(path[::-1])  # Reverse the path to have it from source to sink
        return reversed_paths

    def check_paths_exists_from_sources(self, source, sink: str):
        paths_from_sources = []
        paths = self.get_shortest_paths(
            source_identifier=source,
            target_identifier=sink,
        )
        paths_from_sources.extend(paths)
        return paths_from_sources

    def get_shortest_paths(self, source_identifier, target_identifier,
                        max_depth=10, limit=1000):
        query = self.get_shortest_paths_query(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit,
        )
        return self.execute_neo4j_query_to_get_node_paths(query, source_identifier=source_identifier, target_identifier=target_identifier)
    
    def get_shortest_paths_query(self, source_identifier, target_identifier,
                        max_depth=10, limit=None):
        """
        Generate a Neo4j Cypher query to find paths from CFGFunction nodes to target nodes.
        
        Args:
            target_identifier: List of strings to match against node identifiers
            max_depth: Maximum path length to search
            limit: Optional limit on number of results
        
      
          Returns:
            Rendered Cypher query string
        """

        # Jinja2 template for the Neo4j Cypher query
        template =  Template(SHORTEST_PATH_TEMPLATE.strip())
 
        return template.render(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit
        )

    def get_paths_for_sink(self, source:str, sink: str, max_length: int=10, limit: int=5):
        """
        Get all paths to a sink. 
        We will try all shortest paths from source to sink first.
        If there is not any, we will try paths ending at the sink but not starting from the source.
        """
        paths_from_sources = self.check_paths_exists_from_sources(source, sink)
        if paths_from_sources:
            return paths_from_sources
        # If no paths from sources, try paths ending at the sink
        paths_ending_at_sink = self.get_paths_ending_at(
            end_node=sink,
            max_length=max_length,
            limit=limit
        )
        return paths_ending_at_sink

    # def get_paths_from_harness_to_sink(self, harness_name, sink_funcindex):
    #     # Checks if there exists a patch from source to sink
    #     #print(f"Checking if there exists a path from an harness to {sink_funcindex}")

    #     # NOTE: we are looking for path that have a MAX of 10 hops
    #     # NOTE: we are limiting this search to ONLY 3 paths
    #     query = f"""
    #         MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $harness_name
    #         WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
    #         WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..10]->(end)
    #         RETURN DISTINCT p LIMIT 3
    #     """
    #     params = {
    #         "harness_name": harness_name,
    #         "sink_funcindex": sink_funcindex,
    #     }

    #     results, columns = db.cypher_query(query=query, params=params, resolve_objects = True)

    #     return results

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

    def get_reachable_funcindex(self, harness_prefix):
        """
        Query all sink_funcindex nodes that are reachable within 10 hops from a single harness entry (prefix).
        :param harness_prefix: str, e.g., "LLVMFuzzerTestOneInput"
        :return: list[tuple[str, path]], each sink_funcindex and a corresponding path
        """
        query = """
            MATCH (start:CFGFunction)
            WHERE start.identifier CONTAINS $harness_prefix
            AND NOT start.identifier CONTAINS "LLVMFuzzerInitialize"
            CALL apoc.path.spanningTree(
            start,
            {
                relationshipFilter: 'DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS>',
                maxLevel: 10
            }
            ) YIELD path
            WITH last(nodes(path)) AS endNode
            RETURN DISTINCT endNode.identifier AS sink_funcindex
        """
        params = {
            "harness_prefix": harness_prefix,
        }
        results, columns = db.cypher_query(query=query, params=params)
        return results

    def get_reachable_funcindex_and_paths(self, harness_prefix):
        """
        Query all sink_funcindex nodes that are reachable within 10 hops from a single harness entry (prefix).
        :param harness_prefix: str, e.g., "LLVMFuzzerTestOneInput"
        :return: list[tuple[str, path]], each sink_funcindex and a corresponding path
        """
        query = """
            MATCH (start:CFGFunction)
            WHERE start.identifier CONTAINS $harness_prefix
            AND NOT start.identifier CONTAINS "LLVMFuzzerInitialize"
            CALL apoc.path.spanningTree(
            start,
            {
                relationshipFilter: 'DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS>',
                maxLevel: 10
            }
            ) YIELD path
            WITH last(nodes(path)) AS endNode, path
            WITH endNode.identifier AS sink_funcindex, collect(path)[0..3] AS paths
            UNWIND paths AS path
            RETURN sink_funcindex, path
        """

        params = {
            "harness_prefix": harness_prefix,
        }
        results, columns = db.cypher_query(query=query, params=params)
        return results
    
    def get_more_paths(self, entry_points: List[str]):
        query = """
            MATCH (start:CFGFunction)
            WHERE ANY(prefix IN $entry_points WHERE start.identifier CONTAINS prefix)
            AND NOT start.identifier CONTAINS "LLVMFuzzerInitialize"
            CALL apoc.path.spanningTree(
            start,
            {
                relationshipFilter: 'DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS>',
                maxLevel: 10
            }
            ) YIELD path
            WITH collect(DISTINCT last(nodes(path))) AS sink_nodes, start
            UNWIND sink_nodes AS sink
            WITH sink, start
            WHERE sink.identifier <> start.identifier
            MATCH p = allShortestPaths((start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..10]->(sink))
            WITH sink.identifier AS sink_funcindex, p, length(p) AS path_length
            ORDER BY sink_funcindex, path_length
            WITH sink_funcindex, collect(p)[0..3] AS paths
            UNWIND paths AS path
            RETURN sink_funcindex, path
            ORDER BY sink_funcindex
        """
        params = {
            "entry_points": entry_points,
        }
        results, columns = db.cypher_query(query=query, params=params)
        return results