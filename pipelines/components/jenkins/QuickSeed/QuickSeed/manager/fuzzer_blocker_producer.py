from pathlib import Path
from collections import defaultdict
from typing import Dict
import logging

from .producer import BaseProducer
from ..parser import CoverageAnalysis, TaintParser
from .task import PoisTask
from ..data import Node

_l = logging.getLogger(__name__)


class FuzzerBlockerProducer(BaseProducer):
    def __init__(self, queue, taint_parser: TaintParser, coverage_dir: Path, name=None):
        super().__init__(queue, name)
        self.coverage_dir = coverage_dir
        self.coverage_parser = CoverageAnalysis(self.coverage_dir)
        self.taint_analyzer = taint_parser
        self.nodes = []
        self.edges = []
        self.line_node_mapper = defaultdict(tuple)
        self.coverage_file_mapper = defaultdict(str)
        self.node_id_mapper = {}

    def _check_file_source_exist(self, filename, nodes) -> bool:
        for node in nodes:
            #FIXME: may need is relative to
            if str(node.filepath).endswith(filename):
                # update mapper
                self.coverage_file_mapper[filename] = node.filepath
                if node.is_source:
                    _l.debug(f"we are looking in file {filename}")
                    return True, node.filepath
        return False, ""
    #TODO: double check how to make sure the filepath can be comparable between coverage and our node
    def _create_path_line_node_map(self):
        for node in self.nodes:
            if node.filepath is not None:
                self.line_node_mapper[node.filepath] = (node.func_startline, node.func_endline, node.id)
    def _covert_nodes_to_dict(self) -> Dict[int, Node]:
        for node in self.nodes:
            self.node_id_mapper[node.id] = node
    def operate(self):
        _l.info(f"queue id is {id(self.queue)}")

        use_model_name = 'gpt-4o'
        self.coverage_parser.aggregate_coverage()
        
        coverages = self.coverage_parser.get_individual_coverage()
        coverage_summary = self.coverage_parser.get_summary_coverage()
        self.nodes = self.taint_analyzer.nodes
        self.edges = self.taint_analyzer.edges
        self._create_path_line_node_map()
        self._covert_nodes_to_dict()
        sources, sinks = self.taint_analyzer.retrive_source_sink_from_callgraph()


        # map coverage filename and lineno to our call graph node
        _l.debug(f"coverages is {coverages}")
        # color the graph to show coverage 
        if len(coverages) > 0:
            for file_coverage in coverages:
                file_name = file_coverage.file_name
                _l.debug(f"filename is {file_name}")
                lines_coverage = file_coverage.lines
                file_exits, full_filepath = self._check_file_source_exist(file_name, self.nodes)
                if not file_exits:
                    continue
                
                for line, covered in lines_coverage.items():
                    if not covered:
                        continue
                    startline, endline, node_id = self.line_node_mapper[full_filepath]
                    if startline is None or endline is None:
                        continue
                    if startline < line and line < endline:   
                        _l.debug(f"node {node_id} is covered")
                        self.node_id_mapper[node_id].covered = True
                            
        # covert always missed to id
        always_missed_id = []
        for f, summary in coverage_summary.items():
            filepath = self.coverage_file_mapper[f]
            if filepath == "":
                continue
            _l.debug(f"file is from {filepath}")
            _l.debug(f"summary is {summary}")
            always_missed = summary['always_missed']
            for lineno in always_missed:
                node_map = self.line_node_mapper[filepath]
                if node_map == ():
                    continue
                startline, endline, node_id = node_map
                if startline is None or endline is None:
                        continue
                if startline < lineno and lineno < endline:   
                    _l.debug(f"node {node_id} is covered")
                    always_missed_id.append(node_id)
        _l.debug(f"always missed is {always_missed_id}")
            
        
        # for sources that is covered, see if it can reach a sink, 
        # if so see if there is always miss in the path
        _l.debug(f'source is {sources}')
        for source_node_id in sources:
            
            if self.node_id_mapper[source_node_id].covered:
                _l.debug(f"nodes are covered {self.node_id_mapper[source_node_id]}")
                for sink_node_id in sinks:
                    for path in self.taint_analyzer.retrieve_call_graph_for_llm(source_node_id, sink_node_id):
                        if any([True if node.id in always_missed_id else False for node in path ]):
                            #FIXME: queue must put in task 
                            _l.debug(f"the path to free fuzzer is {[node.funcname for node in path]}")
                            self.queue.put(PoisTask(path, use_model_name))
                        
    
        self.queue.put(None)