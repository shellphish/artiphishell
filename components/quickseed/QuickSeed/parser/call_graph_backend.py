from typing import Optional
from abc import ABC, abstractmethod
from pathlib import Path
from QuickSeed.data import CallGraphNode, CallGraphEdge

class CallGraphBackend(ABC):
    def __init__(self, cp_root: Path, fun_indexer_path: Path, function_json_dir: Path, harnesses_file: list[Path]):
        self.cp_root = cp_root
        self.func_indexer_path = fun_indexer_path
        self.function_json_dir = function_json_dir
        self.harnesses_file = harnesses_file
        self.harnesses_filename = [harness.name for harness in harnesses_file]

    @abstractmethod
    def get_paths(self, *args, **kwargs)-> Optional[list]:
        """
        Get all paths from start_node to end_node.
        Returns a list of paths, where each path is a list of node IDs.
        """
        pass

    @abstractmethod
    def get_shortest_path(self, *args, **kwargs) -> Optional[list]:
        """
        Get the shortest path from start_node to end_node.
        Returns a list of node IDs representing the shortest path, or None if no path exists.
        """
        pass 

    @abstractmethod
    def get_shortest_paths(self, *args, **kwargs) -> Optional[list]:
        """
        Get all shortest paths from start_node to end_node.
        Returns a list of lists, where each inner list is a path represented by node IDs.
        """
        pass

    @abstractmethod
    def get_callers(self, node: CallGraphNode | str) -> Optional[list]:
        """
        Get all callers of a given node.
        Returns a list of node IDs that call the specified node, or None if no callers exist.
        """
        pass

    @abstractmethod
    def get_callees(self, node: CallGraphNode | str) -> Optional[list]:
        """
        Get all callees of a given node.
        Returns a list of node IDs that are called by the specified node, or None if no callees exist.
        """
        pass

    @abstractmethod
    def get_paths_ending_at(self, end_nodes: list[CallGraphNode] | list[str], max_length: Optional[int]=None, limit: Optional[int]=None) -> Optional[list]:
        """
        Get all paths that end at a specified node.
        Returns a list of paths, where each path is a list of node IDs ending at the specified node.
        """
        pass


    @abstractmethod
    def get_sources(self)-> Optional[list]:
        """
        Get all source nodes in the call graph.
        Source nodes are nodes that have no incoming edges.
        Returns a list of node IDs that are source nodes, or None if no source nodes exist.
        """
        pass

    @abstractmethod
    def get_sinks(self) -> Optional[list]:
        """
        Get all sink nodes in the call graph.
        Sink nodes are nodes that have no outgoing edges.
        Returns a list of node IDs that are sink nodes, or None if no sink nodes exist.
        """
        pass
    
    @abstractmethod
    def update_edges_by_yajta_coverage(self, yajta_result):
        """
        Update the edges in the call graph based on Yajta coverage data.
        """
        pass

    @abstractmethod
    def cut_harness_from_path(self, path: list):
        """
        Remove harness nodes from the given path.
        Returns a filtered path with harness nodes removed.
        """
        pass