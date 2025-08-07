import json, threading
from collections import deque
from typing import List
import ipdb
from abc import ABC, abstractmethod
from ..data import Node, Edge
from collections import defaultdict

from ..parser import TaintParser
from .task import HarnessTask

import logging
_l = logging.getLogger(__name__)

class BaseProducer(ABC):
    def __init__(self, queue, name):
        self.queue = queue
        self.name = name
        self.thread = threading.Thread(target=self.operate)
   
    def start(self):
        self.thread.start()
    
    def wait_finish(self):
        self.thread.join()

    @abstractmethod
    def operate(self):
        pass

class Producer(BaseProducer):
    def __init__(self, taint_parser, jazzer_json, queue, name=None):
        self.jazzer_json = jazzer_json
        self.taint_parser = taint_parser
        self.nodes = self.taint_parser.nodes
        self.edges = self.taint_parser.edges
        self.harness_code = ""
        super().__init__(queue, name)

    def finc_source_sink_pair(self) -> List[tuple]:
        src_sink_pairs = []
        for src_node in self.nodes:
            if src_node.is_source and src_node.funcname=="fuzzerTestOneInput":
                for target_node in self.nodes:
                    if target_node.is_sink:
                        if (src_node, target_node) not in src_sink_pairs:
                            src_sink_pairs.append((src_node, target_node))
        return src_sink_pairs

    def convert_source_trace_to_prompt(self, source_and_traces) -> str: 
        prompt = ""
        count = 1
        for node_edge_info in source_and_traces[:-1]:
            src_code = node_edge_info["func_src"]
            linetexts = [lint for lint in node_edge_info["call_linetext"]]
            prompt += f"The source code of function {count} is: \n {src_code}\n"
            prompt += f"The lines of codes that call next function are: \n"
            for line in linetexts:
                prompt += f"{line}\n"
            count += 1       
        prompt += f"The sink method/class calls are the following calls in the last function: \n"
        for line in linetexts:
            prompt += f"{line}\n"
        return prompt
    
    def operate(self):
        _l.info(f"queue id is {id(self.queue)}")
        use_model_name = 'gpt-4o'
        src_sink_pairs = self.finc_source_sink_pair()
        # Order the srource sink pair we get to gurantee diversity
        ordered_source_sink_pair = []
        grouped_dict = defaultdict(list)
        for src, sink in src_sink_pairs:
            if src.filepath:
                grouped_dict[src.filepath].append((src, sink))
        count = 0
        while True:
            length_pre = len(ordered_source_sink_pair)
            for key, value in grouped_dict.items():
                if len(value) > count:
                    ordered_source_sink_pair.append(value[count])
            count += 1
            # ipdb.set_trace()
            if length_pre == len(ordered_source_sink_pair):
                break  
        for src, sink in ordered_source_sink_pair:
            harness_filepath = src.filepath
            if harness_filepath:
                with open(harness_filepath, "r") as f:
                    self.harness_code = f.read()
            path = self.taint_parser.find_shortest_path_bfs(src, sink)
            if path is None:
                continue
            no_harness_path = self.taint_parser.cut_harness_from_path(path)
            source_and_traces = self.taint_parser.retrieve_source_code_for_llm_from_path(no_harness_path)
            trace_info_prompt = self.convert_source_trace_to_prompt(source_and_traces)

            with open(self.jazzer_json, "r") as f:
                jazzer_sanitizer_description = json.load(f)
            _l.debug(f"jazzer sanitizer {jazzer_sanitizer_description}")
            attemps = 2
            if jazzer_sanitizer_description is not None:
                for i in range(attemps):
                    # For now, run two times for the input
                    self.queue.put(HarnessTask(self.harness_code, trace_info_prompt, jazzer_sanitizer_description, use_model_name, harness_filepath))
        self.queue.put(None)

