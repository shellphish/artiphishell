from jinja2 import Template
from typing import Optional
from pathlib import Path
import logging
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from graphquery.graph_client import GraphClient
from QuickSeed.data import CallGraphNode
from QuickSeed.utils import convert_function_resolver_identifier_to_call_graph_node, get_identifier_from_full_name
from QuickSeed.data.metadata import Config
from .call_graph_backend import CallGraphBackend
from .report_parser import CodeQLReportParser
from .assets.cypher_templates import (
    SHORTEST_PATH_TEMPLATE,
    ALL_SHORTEST_PATHS_TEMPLATE,
    ALL_PATHS_TEMPLATE,
    CALLERS_TEMPLATE,
    CALLEES_TEMPLATE,
    ALL_PATHS_ENDING_AT_TEMPLATE,
)
from .path_filter import PathFilter
_l = logging.getLogger(__name__)

class Neo4JBackend(CallGraphBackend):
    """
    Neo4J backend for storing and querying call graphs.
    This backend uses the Neo4J graph database to store call graph data.
    """

    def __init__(self, cp_root: Path, func_indexer_path: Path, func_json_dir: Path, harnesses_file: list[Path],
                 function_resolver: FunctionResolver, sinks: list, report_parser: Optional[CodeQLReportParser] = None,
                 oss_fuzz_build: Optional[OSSFuzzProject] = None):  
        
        super().__init__(cp_root, func_indexer_path, func_json_dir, harnesses_file)
        self.sinks = sinks
        self.function_resolver = function_resolver
        self.report_parser = report_parser
        self.oss_fuzz_build = oss_fuzz_build
        self.sources = self._fetch_sources()
        # self.source_nodes = [convert_function_resolver_identifier_to_call_graph_node(source, self.function_resolver) for source in self.sources]
        # self.source_node_names = [node.qualified_name for node in self.source_nodes]

        # Last hop edges are used to track connections between the last node in the project source to the library sinks.
        # self.last_hop_edges = last_hop_edges if last_hop_edges is not None else []
        
    def get_sources(self):
        """
        Returns the list of source nodes in the call graph.
        """
        return self.sources
    
    def get_sinks(self):
        """
        Returns the list of sink nodes in the call graph.
        """
        return self.sinks
    
    def _fetch_sources(self):
        """
        Fetch source nodes from function resolver.
        """
        sources = list(self.function_resolver.find_by_funcname("fuzzerTestOneInput"))
        sources.extend(list(self.function_resolver.find_functions_with_annotation("@FuzzTest")))
        return sources
    
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

        # Jinja2 template for the Neo4j Cypher query
        template =  Template(ALL_SHORTEST_PATHS_TEMPLATE.strip())
 
        return template.render(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit
        )
        
    def get_shortest_path_query(self, source_identifier, target_identifier,
                        max_depth=10, limit=None):
        """
        Generate a Neo4j Cypher query to find the shortest path from CFGFunction nodes to target nodes. 
        Args:
            target_identifier: List of strings to match against node identifiers
            max_depth: Maximum path length to search
            limit: Optional limit on number of results
        Returns:
            One shortest path
        """
        # Jinja2 template for the Neo4j Cypher query
        template = Template(SHORTEST_PATH_TEMPLATE.strip())
        return template.render(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit
        )
    
    def get_all_paths_query(self, source_identifier: str, target_identifier: str,
                            max_depth: int, limit: int):
        """
        Generate a Neo4j Cypher query to find all paths from CFGFunction nodes to target nodes.
        
        Args:
            target_identifier: List of strings to match against node identifiers
            max_depth: Maximum path length to search
            limit: Optional limit on number of results
        
        Returns:
            Rendered Cypher query string
        """
        cypher_template = Template(ALL_PATHS_TEMPLATE.strip())
        
        return cypher_template.render(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit
        )
    
    def get_callers(self, target_identifier: str):
        """
        Get calller of a specific target identifier.
        Args:
            target_identifier: The identifier of the target node to find callers for.
        Returns:
            Rendered Cypher query string to find callers of the target identifier.
        """
        # Jinja2 template for the Neo4j Cypher query
        cypher_template = Template(CALLERS_TEMPLATE.strip())
        return cypher_template.render(
            target_identifier=target_identifier
        )
    
    def get_callees(self, source_identifier: str):
        """
        Get callees of a specific source identifier.
        Args:
            source_identifier: The identifier of the source node to find callees for.
        Returns:
            Rendered Cypher query string to find callees of the source identifier.
        """
        # Jinja2 template for the Neo4j Cypher query
        cypher_template = Template(CALLEES_TEMPLATE.strip())
        return cypher_template.render(
            source_identifier=source_identifier
        )
    
    def get_paths(self, source_identifier: str, target_identifier: str,
                        max_depth=10, limit=3):
        query = self.get_all_paths_query(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit
        )
        return self.execute_neo4j_query_to_get_node_paths(query, start_identifier=source_identifier, target_identifier=target_identifier)
    
    def get_shortest_path(self, source_identifier, target_identifier,
                        max_depth=10, limit=None):
        query = self.get_shortest_path_query(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit,
        )
        return self.execute_neo4j_query_to_get_node_paths(query, source_identifier=source_identifier, target_identifier=target_identifier)
    
    def update_edges_by_yajta_coverage(self, yajta_result):
        raise NotImplementedError("Neo4JBackend does not support updating edges by Yajta coverage.")
    
    def cut_harness_from_path(self, path: list):
        filtered_path = []
        # harness_path = None
        for node in path:
            if node.filepath.name not in self.harnesses_filename:
                filtered_path.append(node)
        return filtered_path

    def get_shortest_paths(self, source_identifier, target_identifier,
                        max_depth=10, limit=1000):
        query = self.get_shortest_paths_query(
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            max_depth=max_depth,
            limit=limit,
        )
        return self.execute_neo4j_query_to_get_node_paths(query, source_identifier=source_identifier, target_identifier=target_identifier)
        
    def parse_neo4j_path_query_result(self, results, limit: Optional[int]=None):
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
        if limit and len(path_list) > limit:
            path_list = path_list[:limit]
        return path_list
    
    def get_node_paths(self, identifier_paths: list[list[str]])-> list[list[CallGraphNode]]:
        """
        Convert identifier paths to CallGraphNode paths.
        
        Args:
            identifier_paths: List of paths where each path is a list of identifiers.
        
        Returns:
            List of paths where each path is a list of CallGraphNode objects.
        """
        node_paths = []
        for path in identifier_paths:
            # node_path = [convert_function_resolver_identifier_to_call_graph_node(identifier, self.function_resolver) for identifier in path]
            node_path = []
            invalid = False
            for identifier in path:
                node = convert_function_resolver_identifier_to_call_graph_node(identifier, self.function_resolver)
                if node:
                    node_path.append(node)
                else:
                    _l.warning(f"Node with identifier {identifier} not found in function resolver.")
                    invalid = True
                    break
            if not invalid:
                node_paths.append(node_path)
        return node_paths
    
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
        client = GraphClient(query=query)
        query_result = client.execute_query(**kwargs)
        paths = self.parse_neo4j_path_query_result(query_result)
        return self.get_node_paths(paths)
    
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
        if len(reversed_paths) == 0:
            _l.warning(f"No paths found ending at {end_node}.")
            paths = [[end_node]]
            return self.get_node_paths(paths)
        return reversed_paths
    
    def check_paths_exists_from_sources(self, sink: str)-> list[CallGraphNode]:
        paths_from_sources = []
        for source in self.sources:
            paths = self.get_shortest_paths(
                source_identifier=source,
                target_identifier=sink,
            )
            paths_from_sources.extend(paths)
        return paths_from_sources
    
    def get_paths_for_sink(self, sink: str, max_length: int=15, limit: int=5) -> list[CallGraphNode]:
        """
        Get all paths to a sink. 
        We will try all shortest paths from source to sink first.
        If there is not any, we will try paths ending at the sink but not starting from the source.
        """
        paths_from_sources = self.check_paths_exists_from_sources(sink)
        if paths_from_sources:
            return paths_from_sources
        # If no paths from sources, try paths ending at the sink
        paths_ending_at_sink = self.get_paths_ending_at(
            end_node=sink,
            max_length=max_length,
            limit=limit
        )
        return paths_ending_at_sink
    
    def expand_paths_with_codeql_query(self, ranked_paths: list[list[CallGraphNode]]):
        """
        The paths from analysis graph only contains CFG function in target source
        But we need the last node of the path be the library function where the jazzer hooks up.
        So we  need to use codeql query to expand our paths with the last hop nodes
        """
        _l.debug(f"Expanding {len(ranked_paths)} paths with codeql query")
        last_hop_nodes = self.report_parser.sanitizer_nodes
        last_hop_edges = self.report_parser.sanitizer_edges
        last_hop_nodes_dict = {node.id: node for node in last_hop_nodes}
        end_nodes_dict = {}
        for i, path in enumerate(ranked_paths):
            end_nodes = []
            for edge in last_hop_edges:
                start_node_id = edge.source
                start_node = last_hop_nodes_dict.get(start_node_id)
                end_node_id = edge.target
                end_node = last_hop_nodes_dict.get(end_node_id)
                if start_node is not None and start_node.qualified_name == path[-1].qualified_name \
                and end_node is not None and end_node not in end_nodes:
                    end_nodes.append(end_node)
            end_nodes_dict[i] = end_nodes
        expanded_paths = []
        for i, path in enumerate(ranked_paths):
            if i not in end_nodes_dict or len(end_nodes_dict[i]) == 0:
                expanded_paths.append(path)
            else:
                for end_node in end_nodes_dict[i]:
                    expanded_path = path + [end_node]
                    expanded_paths.append(expanded_path)
        _l.debug(f"Expanded {len(ranked_paths)} paths to {len(expanded_paths)} paths")

        return expanded_paths
    
    def paths_with_common_nodes(self, paths: list[list[CallGraphNode]], threshold: int = 10):

        """
        Filter the paths by the last threshold of the paths.
        """
        # min_len = min([len(path) for path in paths])
        max_len = max([len(path) for path in paths])
        if max_len < 2:
            _l.warning(f"Paths are too short: max {max_len}. Cannot filter")
            return paths
        lens = []
        for num in range(max_len, 1, -1):
            filtered_paths = []
            for path in paths:
                if len(path) <= num:
                    filtered_paths.append(tuple(path))
                    continue
                last_nodes = tuple(path[-num:])
                if last_nodes not in filtered_paths:
                    filtered_paths.append(last_nodes)
            if len(filtered_paths) <= threshold:
                _l.debug(f"Filtered paths to {len(filtered_paths)} paths with last {num} nodes")
                return [list(nodes) for nodes in filtered_paths]
            lens.append(filtered_paths)

        _l.warning(f"Cannot filter paths to less than {threshold} paths. Returning the shortest paths")
        min_path_len = len(lens[0])
        for filtered_paths in lens:
            if len(filtered_paths) < min_path_len:
                min_path_len = len(filtered_paths)
                filtered_paths = filtered_paths
        return [list(nodes) for nodes in filtered_paths]
    
    def filter_paths_by_dynamic_call_paths(self, neo4j_paths: list[list[CallGraphNode]],
                                           dynamic_call_paths: list[list[str]]) -> list[list[CallGraphNode]]:
        """
        Filter the Neo4j paths by the dynamic call paths.
        This is to ensure that we only keep the paths that are relevant to the dynamic call paths.
        """
        filtered_paths = []
        source_filter = PathFilter.starts_with_sources(self.sources)
        for path in dynamic_call_paths:
            path_filter = PathFilter.by_ordered_subset(path)
            fpaths = [p for p in neo4j_paths if path_filter(p) and source_filter(p)]
            if len(fpaths) == 0:
                identifier_path = []
                for full_name in path:
                    identifier = get_identifier_from_full_name(self.function_resolver, full_name)
                    if identifier:
                        identifier_path.append(identifier)  
                fpaths = self.get_node_paths([identifier_path])     
            filtered_paths.extend(fpaths)
        return filtered_paths
    
    def rerank_paths_by_filtered_paths(self, paths: list[list[list[CallGraphNode]]]) -> list[list[list[CallGraphNode]]]:
        """
        Rerank the paths by the filtered paths.
        This is to ensure that we prioritize to explore the paths that are relevant to the dynamic call paths.
        """
        reranked_paths = []
        
        path_filter = PathFilter.starts_with_sources(self.sources)
        rerank_rotation_count = Config.rerank_by_source_rotation_count
        path_cluster_starts_with_sources = []
        path_cluster_not_starts_with_sources = []
        processed_count = 0 
        for i, path_cluster in enumerate(paths):
            if len(path_cluster) == 0:
                _l.warning(f"Path cluster {i} is empty. Skipping.")
                continue
            path = path_cluster[0]
            processed_count += 1
            if path_filter(path):
                path_cluster_starts_with_sources.append(path_cluster)
            else:
                path_cluster_not_starts_with_sources.append(path_cluster)
            if processed_count % rerank_rotation_count == 0:
                reranked_paths.extend(path_cluster_starts_with_sources)
                reranked_paths.extend(path_cluster_not_starts_with_sources)
                path_cluster_starts_with_sources = []
                path_cluster_not_starts_with_sources = []
        reranked_paths.extend(path_cluster_starts_with_sources)
        reranked_paths.extend(path_cluster_not_starts_with_sources)
        return reranked_paths