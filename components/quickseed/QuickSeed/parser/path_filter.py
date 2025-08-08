from typing import Callable
from QuickSeed.data import CallGraphNode
import logging
_l = logging.getLogger(__name__)
class PathFilter:
    """Flexible path filtering system"""
    
    @staticmethod
    def by_length(min_length: int = None, max_length: int = None) -> Callable[[list[CallGraphNode]], bool]:
        def filter_func(path: list[CallGraphNode]) -> bool:
            length = len(path.nodes)
            if min_length and length < min_length:
                return False
            if max_length and length > max_length:
                return False
            return True
        return filter_func
    
    @staticmethod
    def contains_node(node_id: str) -> Callable[[list[CallGraphNode]], bool]:
        def filter_func(path: list[CallGraphNode]) -> bool:
            return any(node.id == node_id for node in path.nodes)
        return filter_func
    
    @staticmethod
    def starts_with(node_id: str) -> Callable[[list[CallGraphNode]], bool]:
        def filter_func(path: list[CallGraphNode]) -> bool:
            return len(path.nodes) > 0 and path.nodes[0].id == node_id
        return filter_func
    
    @staticmethod
    def ends_with(node_id: str) -> Callable[[list[CallGraphNode]], bool]:
        def filter_func(path: list[CallGraphNode]) -> bool:
            return len(path.nodes) > 0 and path.nodes[-1].id == node_id
        return filter_func
    
    @staticmethod
    def combine_and(*filters: Callable[[list[CallGraphNode]], bool]) -> Callable[[list[CallGraphNode]], bool]:
        def combined_filter(path: list[CallGraphNode]) -> bool:
            return all(f(path) for f in filters)
        return combined_filter
    
    @staticmethod
    def combine_or(*filters: Callable[[list[CallGraphNode]], bool]) -> Callable[[list[CallGraphNode]], bool]:
        def combined_filter(path: list[CallGraphNode]) -> bool:
            return any(f(path) for f in filters)
        return combined_filter
    
    @staticmethod
    def by_focus_repo(function_resolver) -> Callable[[list[CallGraphNode]], bool]:
        """
        Filter paths that overlap with the focus repository
        
        Args:
            function_resolver: FunctionResolver instance for finding functions
        """
        def filter_func(path: list[CallGraphNode]) -> bool:
            for node in path:
                filepath = node.filepath
                function_name = node.function_name
                
                find_by_filepath = [i for i in function_resolver.find_by_filename(filepath)]
                identifier_by_funcname = [i for i in function_resolver.find_by_funcname(function_name)]
                intersection = list(set(find_by_filepath) & set(identifier_by_funcname))
                
                if (intersection and 
                    function_resolver.get_code(intersection[0])[0]):
                    return True
            return False
        return filter_func
    
    @staticmethod
    def by_diff_change(diff_function_names: list[str]) -> Callable[[list[CallGraphNode]], bool]:
        """
        Filter paths that contain functions changed in a diff
        
        Args:
            diff_function_names: List of function names that were changed in the diff
        """
        def filter_func(path: list[CallGraphNode]) -> bool:
            if not diff_function_names:
                return True  # If no diff functions, include all paths
            
            path_functions = {node.function_name for node in path if node.function_name is not None}
            return any(diff_func in path_functions for diff_func in diff_function_names)
        return filter_func
    
    @staticmethod
    def by_ordered_subset(superset_path: list[str]) -> Callable[[list[CallGraphNode]], bool]:
        def filter_func(path: list[CallGraphNode]) -> bool:
            path_set = set(node.qualified_name for node in path)
            return path_set.issubset(set(superset_path))
        return filter_func
    
    @staticmethod
    def starts_with_sources(sources: list[str]) -> Callable[[list[CallGraphNode]], bool]:
        """
        Filter paths that start with any of the given sources

        Args:
            sources: List of source identifiers (e.g., function names)
        """
        def filter_func(path: list[CallGraphNode]) -> bool:
            if len(path) == 0:
                return False
            node = path[0]
            return node.qualified_name in sources or node.identifier in sources
        return filter_func

def path_rank(path_buckets: list[list[list[CallGraphNode]]], batch_size: int=5, round_robin_size: int=3) -> list[list[CallGraphNode]]:
    """
    Rank paths based on their buckets, using round-robin selection.
    Rank first batch_size buckets paths with the round-robin strategy with the given round_robin_size.
    And then proceed to the next batch_size buckets until we run out of buckets
    """
    _l.debug(f"Ranking paths with round-robin strategy, batch size: {batch_size}, round robin size: {round_robin_size}")
    ranked_paths = []
    total_buckets = len(path_buckets)
    start_bucket = 0
    end_bucket = min(batch_size, total_buckets)
    while start_bucket < total_buckets:
        buckets = path_buckets[start_bucket:end_bucket]
        while any(buckets):
            for i, path_bucket in enumerate(buckets):
                if path_bucket:
                    if len(path_bucket) > round_robin_size:
                        ranked_paths.extend(path_bucket[:round_robin_size])
                        buckets[i] = path_bucket[round_robin_size:]
                    else:
                        ranked_paths.extend(path_bucket)
                        buckets[i] = []
        start_bucket += batch_size
        end_bucket = min(start_bucket + batch_size, total_buckets)
    return ranked_paths
                    