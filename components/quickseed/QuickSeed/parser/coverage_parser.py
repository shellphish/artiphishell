import glob
import json
import logging
import os
import shutil
import tempfile
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from shellphish_crs_utils.models.symbols import SourceLocation
from coveragelib import Tracer, Yajta
from QuickSeed.data import CallGraphNode, CallGraphEdge
from QuickSeed.parser.call_graph_parser import CallGraphParser
from lxml import etree
from pydantic import BaseModel

_l = logging.getLogger(__name__)
logging.getLogger('coveragelib').setLevel(logging.INFO)


class FileCoverage(BaseModel):
    file_name: str
    lines: Dict[int, bool]


class CoverageAnalysis:

    def __init__(self, coverage_build_target, harness_name, seeds_dir, java_tracing_type="jacoco"):

        # TODO: Support more tracing type when we use it on C/C++ projects
        self.coverage_build_target = coverage_build_target
        self.file_line_coverage = defaultdict(dict)
        self.coverage_count = defaultdict(Counter)
        self.total_seeds = 0
        self.all_report_packages = defaultdict(dict)
        if isinstance(seeds_dir, list):
            self.seeds_dir = seeds_dir
        else:
            self.seeds_dir = Path(seeds_dir)
        self.harness_name = harness_name
        if java_tracing_type is not None and java_tracing_type not in ['jacoco', 'yajta']:
            _l.warning(f"Tracing type {java_tracing_type} not supported. Defaulting to jacoco")
            java_tracing_type = 'jacoco'
        self.java_tracing_type = java_tracing_type

    def trace_coverage(self):
        res = None
        if isinstance(self.seeds_dir, list):
            seeds = self.seeds_dir
        else: 
            if self.seeds_dir.is_file():
                seeds = [self.seeds_dir]
            else:
                seeds = [seed for seed in self.seeds_dir.iterdir() if seed.is_file()]
        _l.debug(f"Seeds to trace are {seeds}")
        # On component test, do not rebuild coveragelib image
        if os.getenv("QUICKSEED_DO_NOT_REBUILD_COVERAGE_IMAGE"):
            debug_mode = False
        else:
            debug_mode = True
        if self.java_tracing_type == 'jacoco':
            with Tracer(self.coverage_build_target, self.harness_name, aggregate=True, debug_mode=debug_mode) as tracer:
                res = tracer.trace(*seeds)
        elif self.java_tracing_type == 'yajta':
            with Yajta(self.coverage_build_target, self.harness_name, aggregate=True, debug_mode=debug_mode) as tracer:
                try:
                    res = tracer.trace(*seeds)
                except Exception as e:
                    _l.error(f"Error occurred while tracing with Yajta: {e}")
                    res = None
        return res


    # def parse_btrace_results_to_complete_graph(self, call_graph_parser: CallGraphParser, query_paths: List[List[int]]):
    #     btrace_result_dir = self.target_dir / "work" / "repo_done"
    #     for btrace_result_file in btrace_result_dir.iterdir():
    #         if btrace_result_file.suffix == ".json":
    #             with open(btrace_result_file, 'r') as f:
    #                 btrace_result = json.load(f)
    #                 stack_frames = btrace_result['events']
    #             for path in query_paths:
    #                 node = call_graph_parser.nodes[path[-1]]
    #                 self.find_connected_edge(stack_frames, call_graph_parser, node, path)
    #     return call_graph_parser

    def find_connected_edge(self, stack_frames: List[Dict[str, any]], call_graph_parser: CallGraphParser,
                            node: CallGraphNode, path: List[int]):
        remaining_stack_frames = self.node_in_stack_frame(stack_frames, node)
        if remaining_stack_frames is None:
            return False
        remaining_stack_frames = self.filter_stack_frame_from_path(remaining_stack_frames, path, call_graph_parser)
        existing_node = self.stack_frame_node_in_graph(remaining_stack_frames, call_graph_parser)
        if existing_node is None:
            return False
        edge = {
            'source': node.id,
            'target': existing_node.id
        }
        edge = CallGraphEdge(**edge)

        if edge in call_graph_parser.edges.values():
            return False
        # existing_edge = call_graph_parser.find_edge(edge)
        # if existing_edge:
        #     return False
        # edge['id'] = call_graph_parser.count
        # call_graph_parser.count += 1
        # edge = CallGraphEdge(**edge)
        call_graph_parser.edges[edge.id] = edge
        call_graph_parser.add_edge_to_graph(edge)
        return True

    def node_in_stack_frame(self, stack_frames: List[Dict[str, any]], node: CallGraphNode) -> Optional[
        List[Dict[str, any]]]:
        for i, frame in enumerate(stack_frames):
            if frame['method'] == node.function_name:
                return stack_frames[i + 1:]
        return None

    def stack_frame_node_in_graph(self, stack_frames: List[Dict[str, str]], call_graph_parser: CallGraphParser):
        for frame in stack_frames:
            if not frame['class'].startswith('java.') and not frame['class'].startswith('sun.') \
                    and not frame['class'].startswith('jdk.'):
                method_name = frame['method']
                existing_node = call_graph_parser.function_in_graph(method_name)
                if existing_node:
                    return existing_node
        return None

    def filter_stack_frame_from_path(
            self,
            stack_frames: List[Dict[str, any]],
            path: List[int],
            call_graph_parser: CallGraphParser
    ):
        all_paths_start_with_source = call_graph_parser.all_paths_start_with_source(path[0])

        for p in all_paths_start_with_source:
            if p[:len(path)] == path:
                for node_id in p[len(path):]:
                    node = call_graph_parser.nodes[node_id]
                    for frame in stack_frames:
                        if frame['method'] == node.function_name:
                            stack_frames.remove(frame)
                            break
        return stack_frames

    @staticmethod
    def parse_btrace_result_to_find_stuck_method(
            btrace_filepath: Path,
            node_path: List[CallGraphNode],
    ) -> int:

        with open(str(btrace_filepath), 'r') as f:  
            btrace_result = json.load(f)
            stack_frames = btrace_result['events']
        triggered_methods = [stack_frame['method'] for stack_frame in stack_frames]
        for i, node in enumerate(node_path):
            if node.function_name not in triggered_methods:
                return i - 1
            
    @staticmethod
    def parse_jacoco_result_to_find_stuck_method(
        jacoco_result: list[SourceLocation],
        node_path: List[CallGraphNode],
    ):
        """
        Parse the coverage result and find where the stuck method is in the node path.
        RETURN NONE actually means the whole path is covered
        """
        if node_path[0].qualified_name:
            node_path_methods = [node.qualified_name for node in node_path]
            triggered_methods = [source_location.java_info.full_method_path for source_location in jacoco_result]
        else:
            node_path_methods = [node.function_name for node in node_path]
            triggered_methods = [source_location.function_name for source_location in jacoco_result]
        triggered_methods_on_path = []
        for i, method_name in enumerate(node_path_methods):
            if method_name in triggered_methods:
                triggered_methods_on_path.append(method_name)
        if len(triggered_methods_on_path) == 0:
            return -1
        else:
            stuck_method_index = node_path_methods.index(triggered_methods_on_path[-1])
            if stuck_method_index == len(node_path_methods) - 1:
                return None
            else:
                return stuck_method_index
    
