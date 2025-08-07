
from pathlib import Path
from queue import SimpleQueue
from collections import deque
from typing import List, Dict, Optional, Generator, Set

import json
import yaml
import logging
import sys

from QuickSeed.data import Node, Edge, Graph, Program
from QuickSeed.utils import absolute_path_finder
from graphviz import Digraph

SANITIZER_QUERY_KEYS = [
    "CommandInjection",
    "SSRF",
    "Deserialization",
    "ExpressionLanguage",
    "FileSystem",
    "NamingContextLookup",
    "LdapInjection"
]

_l = logging.getLogger(__name__)
class TaintParser:
    def __init__(
            self,
            program: Program,
            antlr: Path = None,
            func_indexer: Path = None,
    ):
        # We assume the report we get is a csv file
        self.taint_report = program.report
        self.program = program
        self.src_root = program.src_root
        self.count = 0
        self.vuln_type = ""
        self.nodes = []
        self.edges = []
        self.harnesses_file = []
        self.parse()
        if not antlr.exists():
            raise ValueError("The antlr folder does not exist")
        if not func_indexer.exists():
            raise ValueError("The function indexer file does not exist")

        with open(func_indexer, "r") as f:
            self.func_indexer = json.load(f)
        self.antlr = antlr
        if self.antlr and self.func_indexer:
            self.code_parse()

    def parse(self)->None:
        with open(self.taint_report, "r") as f:
            report = yaml.safe_load(f)
        _l.debug(f"taint_report path is {self.taint_report}")
        edges = []
        for qlname, qledges in report.items():
            if qlname in SANITIZER_QUERY_KEYS:
                edges += qledges.get("#select").get("tuples")
        _l.debug(f"The edges are {edges}")
        _l.debug(f"The result we get from codeql is {edges}")
        self.extract_harness_files(edges)
        for edge in edges:
            source_func = edge[0].get("label")
            target_func = edge[1].get("label")

            target_func_call_loc_file = edge[2]

            target_func_call_loc_line = int(edge[3])
            source_func_loc_file = edge[4]
            source_func_line = edge[5] 
            target_func_loc_file = edge[6]
            target_fun_line = edge[7]
            sanitizer = edge[8]
            dest_loc = edge[9].get("label")
            if source_func == "fuzzerTestOneInput":
                is_source = True
            else:
                is_source = False
            if source_func_loc_file in self.harnesses_file:
                is_src_harness = True
            else:
                is_src_harness = False
            if target_func_loc_file in self.harnesses_file:
                is_target_harness = True
            else:
                is_target_harness = False
            if dest_loc[7:].startswith(target_func_loc_file):
                is_sink = True
            else:
                is_sink = False
            if is_source:
                node_a_color = "red"
            else:
                node_a_color = "blue"
            if is_sink:
                node_b_color = "red"
            else:
                node_b_color = "blue"
            node_a = {
                "id": self.count,
                "funcname": source_func,
                "filepath": absolute_path_finder(self.src_root, source_func_loc_file),
                "is_source": is_source,
                "is_sink": False,
                "color": node_a_color,
                "is_harness": is_src_harness,
                "next_nodes": []
            }
            _l.debug(f"node_a is currently {node_a}, original filepath is {source_func_loc_file}")
            existing_node_a = self.exist(node_a)
            if existing_node_a:
                node_a = existing_node_a
                node_a.is_sink = False
                node_a.is_source = is_source
                node_a.is_harness = is_src_harness
            else:
                self.count+=1
                # node_a["is_source"] = False
                # node_a["is_sink"] = False

                node_a = Node(**node_a)
                self.nodes.append(node_a)

            
            node_b = {
                "id": self.count,
                "funcname": target_func,
                "filepath": absolute_path_finder(self.src_root, target_func_loc_file),
                "is_source": is_src_harness,
                "is_sink": is_sink,
                "color": node_b_color,
                "is_harness": is_target_harness,
                "next_nodes": []
            }
            _l.debug(f"node_b currently is {node_b}, original filepath is {target_func_loc_file}")
            existing_node_b = self.exist(node_b)
            if existing_node_b:
                node_b = existing_node_b
                node_b.is_sink = is_sink
                node_b.is_source = is_src_harness
                node_b.is_harness = is_target_harness
            else:
                self.count += 1
                node_b = Node(**node_b)
                self.nodes.append(node_b)
            _l.debug(target_func_call_loc_file)
            edge = {
                "id": self.count,
                "lineno": target_func_call_loc_line,
                "source": node_a.id,
                "target": node_b.id,
                "filepath": absolute_path_finder(self.src_root, target_func_call_loc_file),
            }
            _l.debug(f"edge is currently {edge}, original filepath is {target_func_call_loc_file}")

            if node_b.id not in node_a.next_nodes:
                node_a.next_nodes.append(node_b.id)

            self.count += 1
            self.edges.append(Edge(**edge))
        graph = {
            "nodes": self.nodes,
            "edges": self.edges
        }
        self.graph = Graph(**graph)

    def extract_harness_files(self, edges_list: List):
        for edge in edges_list:
            if edge[0].get("label") == "fuzzerTestOneInput":
                self.harnesses_file.append(edge[4])
    
    def code_parse(self):
        if not self.nodes:
            _l.warning("The graph is empty. Nothing to parse for.")  
            exit(1)
        for node in self.nodes:
            src = self.retrieve_src(node)
        
        self.line_parse()
            
    
    def line_parse(self):
        for edge in self.edges:
            with open(edge.filepath, "r") as f:
                codes = f.read().replace("\\n", "\n")
                edge.linetext = codes.split("\n")[edge.lineno-1]

    def retrieve_src(self, node: Node) -> Optional[str]:
        for key_index, func_info_path in self.func_indexer.items():
            key_split = key_index.split(":")
            # _l.debug(f"file path of node is {node.filepath}, key_split is {key_split}")

            if str(node.filepath).endswith(key_split[0]) and node.funcname in key_index:

                with open(self.antlr/func_info_path, "r") as f:
                    func_info = json.load(f)
                    node.func_src = func_info.get("code", None)
                    node.func_startline =  int(func_info.get("start_line", None))
                    node.func_endline = int(func_info.get("end_line", None))
                    return
        _l.warning(f"Cannot retrieve source code from {node.filepath}. It is probably a library function. Skipping")
        
    
    def exist(self, node: Dict) -> Optional[Node]:
        for n in self.nodes:
            if node["funcname"] == n.funcname and \
                node["filepath"] == n.filepath:
                return n
        return None
    

    def visualize_graph(self):
        dot = Digraph(comment = "Taint Analysis Graph")

        for node in self.graph.nodes:
            dot.node(str(node.id), node.funcname, color=node.color)

        for edge in self.graph.edges:
            dot.edge(str(edge.source), str(edge.target), label=edge.linetext, color=edge.color)
        
        dot.render("taint_analysis_grpah.gv", view=False)

    def find_shortest_path_bfs(self, source_node, sink_node):
        explored = []
        queue = deque([[source_node]])
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node not in explored:
                next_nodes = self.find_node_by_id(node.next_nodes)
                for n_node in next_nodes:
                    new_path = list(path)
                    new_path.append(n_node)
                    queue.append(new_path)
                    if n_node == sink_node:
                        return new_path
                explored.append(node)
        return None
        
    def find_node_by_id(self, node_ids: List[int]) -> List[Node]:
        nodes = []
        for node in self.nodes:
            if node.id in node_ids:
                nodes.append(node)
        return nodes
    
    def find_edge_by_src_target(self, src_node: Node, target_node: Node) -> List[Edge]:
        edge_sets = []
        for edge in self.edges:
            if edge.source == src_node.id and edge.target == target_node.id:
                edge_sets.append(edge)
        return edge_sets
    
    def retrieve_harness_source_for_path(self, path: List[Node]):
        for node in path:
            for n in self.nodes:
                if n.is_harness and n.funcname == "fuzzerTestOneInput":
                    p = self.find_shortest_path_bfs(n, node)
                    if p is not None and len(p) >= 1:
                        return n.filepath
        return None

    def retrieve_source_code_for_llm_from_path(self, path: List[Node]) -> List[Dict]:
        # FIXME: For now we assume the last expr of last funciton in dictionary is the sink. Fix in the future
        function_sources = []
        for i, node in enumerate(path):
            node_dict_info = {
                "call_lineno": [],
                "call_linetext": [],
                "call_filepath": [],
                "func_src": node.func_src,
                "func_startline": node.func_startline,
                "func_endline": node.func_endline                
            }
            if i+1 < len(path):
                edge_sets = self.find_edge_by_src_target(path[i], path[i+1])
                for e in edge_sets:
                    node_dict_info["call_lineno"].append(e.lineno)
                    node_dict_info["call_linetext"].append(e.linetext)
                    node_dict_info["call_filepath"].append(e.filepath)
            function_sources.append(node_dict_info)
        return function_sources
    def cut_harness_from_path(self, path: List):
        filtered_path = []
        for node in path:
            if node.funcname == "fuzzerTestOneInput" and node.is_source:
                harness_path = node.filepath
            
            if node.filepath != harness_path:
                filtered_path.append(node)
        return filtered_path
        
    def retrive_source_sink_from_callgraph(self):
        # retrieve a node id for sources and sinks
        sources = []
        sinks = []
        for node in self.nodes:
            if node.is_source and node.is_harness:
                sources.append(node.id)
            if node.is_sink:
                sinks.append(node.id)
        return sources, sinks
        

    def covert_nodes_to_dict(self) -> Dict[int, Node]:
        node_id_map = {}
        for node in self.nodes:
            node_id_map[node.id] = node
        return node_id_map 
    def minimize_call_trace(self, node_path: List[Node]) -> List[Node]:
        prev_node = node_path[0]
        result_list = [prev_node]
        for node in node_path[1:]:
            if node.funcname == prev_node.funcname and node.filepath == prev_node.filepath:
                continue
            else:
                result_list.append(node)
                prev_node = node
        return result_list
            
        
    def retrieve_call_graph_for_llm(self, source_id, sink_id) -> Generator[List[Node], None, None]:
        node_id_map = self.covert_nodes_to_dict()
        stack = list() # stack of nodes
        cur_node = node_id_map[source_id]
        
        stack.append((cur_node, [cur_node]))
        while len(stack) > 0:
            visit_node, node_path = stack.pop()
                
            if visit_node.id == sink_id:
                yield self.minimize_call_trace(list(node_path))
            else:
                # need to map id to node
                for next_node_id in visit_node.next_nodes:
                    next_node = node_id_map[next_node_id]
                    if next_node not in node_path:
                        stack.append((next_node, node_path + [next_node]))



                

    

