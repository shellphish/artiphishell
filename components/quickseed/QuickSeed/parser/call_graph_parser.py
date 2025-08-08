import json
import logging
import os
import random
import re
from collections import deque, defaultdict
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Generator, Tuple
from uuid import UUID, uuid4
from itertools import zip_longest

import tempfile
from jinja2 import Template
import multiprocessing as mp
from tqdm import tqdm

import networkx as nx
from shellphish_crs_utils.function_resolver import FunctionResolver
from QuickSeed.data import CallGraphNode
from QuickSeed.utils import parse_yajta_result
from QuickSeed.utils import convert_function_resolver_identifier_to_call_graph_node


_l = logging.getLogger(__name__)

class CallGraphParser:
    def __init__(
        self,
        function_resolver: FunctionResolver,
        sources: List[str],
        codeswipe_func_names: List[str],
            # If sink type is commit, we need this to extract commit changed functions
    ):
        self.graphs: Dict[str, nx.DiGraph] = {}
        self.function_resolver = function_resolver
        self.sources = sources
        self.codeswipe_func_names = codeswipe_func_names
        # self.source_nodes = [convert_function_resolver_identifier_to_call_graph_node(identifier, self.function_resolver) for identifier in sources]
        self.source_nodes = []
        for identifier in sources:
            node = convert_function_resolver_identifier_to_call_graph_node(identifier, self.function_resolver)
            if node:
                self.source_nodes.append(node)
        self.source_node_names = [node.qualified_name for node in self.source_nodes]
        self.all_paths_from_sources_to_sinks: List[List[str]] = []

    def get_all_shortest_paths_from_source_to_sink(self) -> List[List[CallGraphNode]]:
        all_shortest_paths = []
        source_sink_pairs = self.source_sink_pairs()
        for src, sink in source_sink_pairs:
            paths = self.all_shortest_paths_from_one_source_to_one_sink(src.id, sink.id)
            new_paths = self.paths_mapping_from_UUID_to_CallGraphNode(paths)
            all_shortest_paths.extend(new_paths)
        return all_shortest_paths
    
    def all_shortest_paths_from_one_source_to_one_sink(self, source_id: UUID, sink_id: UUID) -> List[List[UUID]]:
        if source_id not in self.graph or sink_id not in self.graph:
            return []
    
        # Then check if there's a path between them using has_path
        if not nx.has_path(self.graph, source_id, sink_id):
            return []
        
        try:
            paths = nx.all_shortest_paths(self.graph, source_id, sink_id)
        except nx.NetworkXNoPath:
            return []
        paths = list(paths)

        return paths

    def all_paths_from_one_source_to_one_sink(self, source_id: int, sink_id: int) -> List[List[List]]:
        try:
            paths = nx.all_simple_paths(self.graph, source_id, sink_id)
            paths = list(paths)
            return paths
        except nx.NetworkXNoPath:
            return []
        
    def cut_harness_from_path(self, path: List):
        filtered_path = []
        # harness_path = None
        for node in path:
            if node.filepath not in self.harnesses_file:
                filtered_path.append(node)
        return filtered_path

    
    def filter_path_by_tests(self, paths: List[List[UUID]]) -> List[List[UUID]]:
        """
        Filter out paths that have test case
        """
        _l.debug(f"Filteing paths that have test cases")
        to_be_removed = []
        for i, path in enumerate(paths):
            for node_id in path:
                if "test" in self.nodes[node_id].function_name or "Test" in self.nodes[node_id].filepath.name:
                    to_be_removed.append(i)
                    break
        return [path for i, path in enumerate(paths) if i not in to_be_removed]
            
    def filter_path_by_sink(self, paths: List[List[UUID]], sink_node: UUID) -> List[List[UUID]]:
        """
        Filter paths that end with the sink node
        """

        _l.debug(f"Filtering paths by sink node {sink_node}")
        filtered_paths = []

        for i, path in enumerate(paths):
            if path[-1] == sink_node and path not in filtered_paths:
                filtered_paths.append(path)
        return filtered_paths
    
    def filter_path_by_harness(self, paths: List[List[CallGraphNode]]) -> List[List[CallGraphNode]]:
        """
        Filter paths that start with fuzzerTestOneInput
        """
        _l.debug(f"Filtering paths by harness")
        filtered_paths = []
        for path in paths:
            if path[0].function_name == "fuzzerTestOneInput":
                filtered_paths.append(path)
        return filtered_paths
    
    def filter_path_by_data_flow_analysis(self, paths: List[List[UUID]]) -> List[List[UUID]]:
        """
        Filter out paths that do not have data flow
        """
        all_sink_node_ids = []
        path_dict_by_sink_node = {}
        for path in paths:
            if path[-1] not in all_sink_node_ids:
                all_sink_node_ids.append(path[-1])
                path_dict_by_sink_node[path[-1]] = [path]
            else:
                path_dict_by_sink_node[path[-1]].append(path)
        

    def codeql_server_enabled(self):
        if self.client == None or self.project_id == None or self.project_name == None:
            _l.warning(f"CodeQL not enbaled cannot query")
            return False
        return True
 
    def get_paths_of_length_ending_at(self, graph: nx.DiGraph, target_node_id: str, max_length: int=2, shortest: bool = False, all: bool=False)->List[UUID]:
        """
        Find all paths up to max_length that end at the target node.
        Include shorter paths if they start at nodes with no predecessors.
        
        Parameters:
        G (nx.DiGraph): A directed graph
        target_node: The node where paths should end
        max_length: The maximum path length
        
        Returns:
        list: List of all valid paths ending at target_node
        """
        all_paths = []
        
        # Use BFS starting from the target and moving backwards
        queue = deque([(target_node_id, [target_node_id], 1)])
        visited_path_states = set()  # To avoid processing the same state twice
        starting_nodes = []
        while queue:
            node, path, depth = queue.popleft()
            
            # Add this path if it starts with a source node (no predecessors)
            # or if we've reached the maximum depth
            if depth > 1:  # Ensure the path has at least one edge
                if depth >= max_length or len(list(graph.predecessors(path[0]))) == 0:
                    # Reverse the path to get the correct direction
                    # If the shortest is set, we only want the shortest 
                    if shortest and not all and path[0] in [sp[0] for sp in starting_nodes]:
                        continue
                    skip = False
                    if shortest and all:
                        for sp in starting_nodes:
                            if path[0] == sp[0] and len(path) > sp[1]:
                                skip = True
                                break
                        if skip:
                            continue
                    if list(path) not in all_paths:
                        all_paths.append(list(path))
                        starting_nodes.append((path[0], len(path)))
                if depth > max_length:
                    continue
            
            # If we haven't reached max depth, continue exploring
            if depth < max_length:
                for pred in graph.predecessors(node):
                    # Avoid cycles in the path
                    if pred not in path:
                        new_path = [pred] + path
                        new_state = (pred, tuple(new_path))
                        if new_state not in visited_path_states:
                            visited_path_states.add(new_state)
                            queue.append((pred, new_path, depth + 1))
        return all_paths

    
    
    def filter_paths_by_focus_repo(self, paths: List[List[UUID]], function_resolver: FunctionResolver)->List[List[UUID]]:
        """
        Filter out paths that are not in the focus repo
        """
        filtered_paths = []
        
        for path in paths:
            overlap_with_focus_repo = False
            for node_id in path:
                filepath = self.nodes[node_id].filepath
                function_name = self.nodes[node_id].function_name
                find_by_filepath = [i for i in function_resolver.find_by_filename(filepath)]
                identifier_by_funcname = [i for i in function_resolver.find_by_funcname(function_name)]
                intersection = list(set(find_by_filepath) & set(identifier_by_funcname))
                if intersection and function_resolver.get_code(intersection[0])[0] and not self._in_source_harness_filepaths(filepath):
                    overlap_with_focus_repo = True
                    break
            if overlap_with_focus_repo:
                filtered_paths.append(path)
        return filtered_paths
    
    
    def update_edges_by_yajta_coverage(self, harness_name: str, yajta_results: List):
        """
        Update the edges by the yajta coverage
        """
        import time
        t1 = time.time()
        if harness_name not in self.graphs:
            self.graphs[harness_name] = nx.DiGraph()
        graph = self.graphs[harness_name]
        _l.debug(f"Updating edges by yajta coverage for {harness_name} with {len(graph.nodes())} nodes and {len(graph.edges())} edges")
        for yajta_result in yajta_results:
            visited, edges = parse_yajta_result(yajta_result.get("children"))
            for edge in edges:
                source_node_qualified_name = edge[0].split("(")[0]
                target_node_qualified_name = edge[1].split("(")[0]
                graph.add_node(source_node_qualified_name)
                graph.add_node(target_node_qualified_name)
                graph.add_edge(source_node_qualified_name, target_node_qualified_name)
        t2 = time.time()
        _l.debug(f"Updated edges by yajta coverage in {t2 - t1} seconds")
        _l.debug(f" ✅ Graph of harness {harness_name} has {len(graph.nodes())} nodes and {len(graph.edges())} edges after update")
    

    def get_paths_ending_at_sink_node_ids(self, function_resolver: FunctionResolver, threshold=10):
        _l.debug(f"📍 Getting all paths ending at sinks.")
        for vuln_type, sink_node_ids in self.sink_node_ids_by_type.items():

            if vuln_type == "Diff" and len(self.all_paths_ending_at_sinks[vuln_type]) > 0:
                continue
            # self.all_paths_from_source_to_sink[vuln_type] = []
            paths_ending_at_nodes = self.get_paths_of_length_ending_at_nodes(sink_node_ids, length=threshold)
            paths_ending_at_nodes = self.filter_path_by_tests(paths_ending_at_nodes)
            paths_ending_at_nodes = self.filter_paths_by_focus_repo(paths_ending_at_nodes, function_resolver)
            # Save all the paths ending at sink nodes for every vulnerability type
            self.all_paths_ending_at_sinks[vuln_type] = paths_ending_at_nodes
            
    
    def filter_paths_by_sublist(self, paths: List[List[UUID]]):
        path_sets = [frozenset(path) for path in paths]
        indice_to_be_removed = []
        for i, path in enumerate(path_sets):
            for j in range(i + 1, len(path_sets)):
                if len(path & path_sets[j]) == len(path):
                    indice_to_be_removed.append(i)
                if len(path & path_sets[j]) == len(path_sets[j]):
                    indice_to_be_removed.append(j)

        return [path for i, path in enumerate(paths) if i not in indice_to_be_removed]

    def filter_pass(self, paths: List[List[UUID]], function_resolver: FunctionResolver):
        filtered_paths = self.filter_path_by_tests(paths)
        # filtered_paths = self.filter_path_by_harness(filtered_paths)
        filtered_paths = self.filter_paths_by_focus_repo(filtered_paths, function_resolver)
        return filtered_paths

 

    def update_paths_ending_at_sink_node_ids(self, function_resolver, vuln_types: List[str]):
        _l.debug(f"📍 Getting all paths ending at sinks.")
        for vuln_type, sink_node_ids in self.sink_node_ids_by_type.items():
            if vuln_type not in vuln_types:
                continue
            if vuln_type == "Diff" and len(self.all_paths_ending_at_sinks[vuln_type]) > 0:
                continue
            # self.all_paths_from_source_to_sink[vuln_type] = []
            paths_ending_at_nodes = self.get_paths_of_length_ending_at_nodes(sink_node_ids, length=10)
            paths_ending_at_nodes = self.filter_path_by_tests(paths_ending_at_nodes)
            paths_ending_at_nodes = self.filter_paths_by_focus_repo(paths_ending_at_nodes, function_resolver)
            # Save all the paths ending at sink nodes for every vulnerability type
            self.all_paths_ending_at_sinks[vuln_type] = paths_ending_at_nodes
    
    def update_all_paths_from_source_to_sink(self, vuln_types: List[str]):
        for vuln_type, sink_node_ids in self.sink_node_ids_by_type.items():
            if vuln_type not in vuln_types:
                continue
            all_paths = []
            _l.debug(f"There are {len(sink_node_ids)} sinks of type {vuln_type}") 
            for node_id in self.source_node_ids:
                for sink_id in sink_node_ids:
                    new_paths = self.all_shortest_paths_from_one_source_to_one_sink(node_id, sink_id)
                    new_paths = self.filter_path_by_tests(new_paths)
                    # For paths from source to sink, we want to keep the original path and have new paths
                    self.all_paths_from_source_to_sink[vuln_type].extend(new_paths)
                    if len(new_paths) == 0:
                        new_paths = self.get_paths_of_length_ending_at(sink_id, max_length=6)
                        all_paths.extend(new_paths)
            # For this we want to completely update the paths
            self.all_paths_ending_at_sinks_when_no_path_from_source[vuln_type] = all_paths

    
    
    def get_dynamic_paths_from_sources_to_sinks(self):
        """
        Get paths ending at sinks.
        This is a placeholder method and should be implemented in subclasses.
        """
        all_paths = []
        # sources = self.call_graph_parser.get_sources()
        # source_nodes = [convert_function_resolver_identifier_to_call_graph_node(identifier, self.function_resolver) for identifier in sources]
        # source_node_names = [node.qualified_name for node in source_nodes]
        for funcname in self.codeswipe_func_names:
            paths = []
            _l.debug(f"Processing function: {funcname}")
            # Here you would implement the logic to get paths ending at sinks
            # For example, you might call a method from the call graph parser
            # or filter paths based on some criteria.
            # This is just a placeholder for demonstration purposes.
            for harness_name, graph in self.graphs.items():
                if funcname not in graph:
                    _l.warning(f"Function {funcname} not found in the dynamic call graph for harness {harness_name}, skipping")
                    continue
                paths_ends_at_sinks = self.get_paths_of_length_ending_at(graph, funcname, max_length=15)
                for path in paths_ends_at_sinks:
                    for i, node in enumerate(path):
                        if node in self.source_node_names:
                            _l.info(f"Found a path ending at {funcname} with fuzzerTestOneInput: {path}")
                            paths.append(path[i:])
                            break
            all_paths.append(paths)
        self.all_paths_from_sources_to_sinks = all_paths
        return all_paths

    def clear_graphs(self):
        """
        Clear the graphs
        """
        _l.debug("Clearing all graphs")
        try:
            self.graphs.clear()
        except Exception as e:
            _l.error(f"Failed to clear graphs cleanly", exc_info=True)
        self.graphs = {}

