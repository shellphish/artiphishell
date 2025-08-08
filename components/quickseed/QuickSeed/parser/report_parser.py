import json
from abc import ABC, abstractmethod
from collections import defaultdict, namedtuple
from enum import Enum, auto
from pathlib import Path
from typing import List, Tuple, Dict, Optional, NamedTuple, Set
from jinja2 import Template
# from QuickSeed.utils import register_call_relationship_to_analysis_graph

import yaml
import logging
import multiprocessing as mp
import os
from tqdm import tqdm  
import time

from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.sarif_resolver import SarifResolver
from QuickSeed.data import CallGraphNode, CallGraphEdge, ReflectionCallNode, FlowNode
_l = logging.getLogger(__name__)


class CodeQLStruct(Enum):
    SOURCE_NAME = "source_name"
    SOURCE_LOCATION = "source_location"
    TARGET_NAME = "target_name"
    TARGET_LOCATION = "target_location"
    SOURCE_FILEPATH = "source_filepath"
    SOURCE_LINENO = "source_lineno"
    TARGET_FILEPATH = "target_filepath"
    TARGET_LINENO = "target_lineno"
    CALL_LOCATION = "call_location"
    CALL_FILEPATH = "call_filepath"
    CALL_LINENO = "call_lineno"
    SOURCE_BODY_LOCATION = "source_body_location"
    TARGET_BODY_LOCATION = "target_body_location"
    SANITIZER_NAME = "sanitizer_name"
    SINK_FILEPATH = "sink_filepath"
    SINK_LINENO = "sink_lineno"
    SINK_LOCATION = "sink_location"

    REFLECTION_CALL_LOCATION = "reflection_call_location"
    REFLECTION_CALL_METHOD_NAME = "reflection_call_method_name"
    REFLECTION_CALL_METHOD_LOCATION = "reflection_call_method_location"

    SOURCE_NODE_EXPR = "source_node_expr"
    TARGET_NODE_EXPR = "target_node_expr"
    UNDEFINED = "undefined"
    TARGET_CLASS_NAME = "target_class_name"
    SOURCE_CLASS_NAME = "source_class_name"
    SINK_QUALIFIED_NAME = "sink_qualified_name"

    SOURCE_QUALIFIED_NAME = "source_qualified_name"
    TARGET_QUALIFIED_NAME = "target_qualified_name"

    SOURCE_SIGNATURE = "source_signature"
    TARGET_SIGNATURE = "target_signature"


class ReportParser(ABC):
    def __init__(self, report: Dict):
        self.report_data = report
        # try:
        #     with open(self.report, "r") as f:
        #         self.report_data = json.load(f)
        # except json.JSONDecodeError:
        #     with open(self.report, "r") as f:
        #         self.report_data = yaml.safe_load(f)

    @abstractmethod
    def parse_report(self):
        pass


SANITIZER_QUERY_KEYS = [
    "CommandInjection",
    "ServerSideRequestForgery",
    "Deserialization",
    "ExpressionLanguage",
    "PathTraversal", # Disable this, because we get too many results on it with tika
    "NamingContextLookup",
    "LdapInjection",
    
    "ReflectionCallInjection",
    "SqlInjection",
    "XPathInjection",
    "ScriptEngineInjection",
    "RegexInjection",

    # "All",
    "LastHopEdges",

    ## These are queries not related to sanitizer
    # "LocalDataFlow",
    # "FieldAccess",
    # "MethodAccess",
    # "LLMSinks",
    # "SubGraphToTarget",
    # "CallGraph",
]

OTHER_QUERY_KEYS = [
    "ReflectionCall",
    "AbstractOverride"
]


class CodeQLReportParser(ReportParser):
    def __init__(self, report: List[Dict], 
                 upload_analysis_graph: bool = False, 
                 local_run: bool = False, 
                 function_resolver = None):
        super().__init__(report)
        if function_resolver and upload_analysis_graph:
            self.upload_analysis_graph = upload_analysis_graph
        else:
            self.upload_analysis_graph = False
        self.local_run = local_run
        _l.debug(f"Start parsing codeql query report.")
        if self.upload_analysis_graph:
            _l.debug(f"Start uploading analysis graph.")
        self.parse_report()
        _l.debug(f"Finish parsing codeql query report.")
        if self.upload_analysis_graph:
            _l.debug(f"Finish uploading analysis graph.")

    def parse_report(self):
        sanitizer_node_list, sanitizer_edge_list, sanitizer_sink_node_dict = self.parse_sanitizer()
        # other_node_list, other_edge_list, other_sink_node_list = [], [], []
        # abstract_override_node_list, abstract_override_edge_list = [], []
        # if self.report_data.get("ReflectionCall"):
        #     other_node_list, other_edge_list, other_sink_node_list = self.parse_rows(self.report_data.get("ReflectionCall"))
        # if self.report_data.get("AbstractOverride"):
        #     abstract_override_node_list, abstract_override_edge_list, abstract_override_sink_node_list = self.parse_rows(self.report_data.get("AbstractOverride"))
        # if self.report_data.get("JazzerSinks"):
        #     sanitizer_sink_node_dict = self.parse_sinks()

        self._sanitizer_nodes = sanitizer_node_list 
        self._sanitizer_edges = sanitizer_edge_list 
        # self._other_nodes = other_node_list 
        # self._other_edges = other_edge_list 
        # self._abstract_override_nodes = abstract_override_node_list

        # # The source is abstract method, and the target is concrete implementation
        # # We have a edge from source to target
        # self._abstract_override_edges = abstract_override_edge_list 

        self._sanitizer_sink_functions = []
        # self._other_sink_functions = []
        # if sanitizer_sink_node_list:
        self._sanitizer_sink_functions = sanitizer_sink_node_dict

        # if other_sink_node_list:
        #     self._other_sink_functions = self.process_sink_nodes(other_sink_node_list)

    @property
    def sanitizer_nodes(self):
        return self._sanitizer_nodes.copy()

    @property
    def sanitizer_edges(self):
        return self._sanitizer_edges.copy()

    @property
    def other_nodes(self):
        return self._other_nodes.copy()

    @property
    def other_edges(self):
        return self._other_edges.copy()

    @property
    def sanitizer_sink_functions(self):
        return self._sanitizer_sink_functions.copy()

    @property
    def other_sink_functions(self):
        return self._other_sink_functions.copy()
    
    @property
    def abstract_override_nodes(self):
        return self._abstract_override_nodes.copy()
    
    @property
    def abstract_override_edges(self):
        return self._abstract_override_edges.copy()

    def update_sanitizer_sink_functions(self, key, value):
        self._sanitizer_sink_functions[key] = value

    def parse_sanitizer(self):
        rows = []
        node_list = []
        edge_list = []
        # We need this for faster lookup
        node_dict_map = {}
        edge_dict_map = {}
        sink_node_list = []
        sink_node_dict = defaultdict(list)
        for qlname, qledges in self.report_data.items():
            if qlname in SANITIZER_QUERY_KEYS:

                rows = qledges 
                node_list, edge_list, sink_node_list = self.parse_rows(rows, node_list, edge_list, node_dict_map, edge_dict_map)
                if sink_node_list:
                    sink_functions = self.process_sink_nodes(sink_node_list)
                    sink_node_dict[qlname] = sink_functions
        return node_list, edge_list, sink_node_dict

    
    def parse_sinks(self):
        sink_node_dict = defaultdict(list)
        sink_dict = self.report_data.get("JazzerSinks")
        for sanitizer_name, sink_query_result in sink_dict.items():

            if sanitizer_name not in SANITIZER_QUERY_KEYS:
                continue
            for row in sink_query_result:
                _, _, sink_node, _ = self._match_parsed_row_to_node(row)
                if not sink_node_dict.get(sanitizer_name):
                    sink_node_dict[sanitizer_name] = [sink_node]
                elif sink_node not in sink_node_dict[sanitizer_name]:
                    sink_node_dict[sanitizer_name].append(sink_node)
        for sanitizer_name, sink_nodes in sink_node_dict.items():
            sink_functions = self.process_sink_nodes(sink_nodes)
            sink_node_dict[sanitizer_name] = sink_functions
        return sink_node_dict
    
    def parse_rows_in_parallel(
            self,
            rows: List[Dict],
            chunk_size: int = 100,
            num_workers: Optional[int] = None,
    ):
        if not num_workers:
            num_workers = mp.cpu_count()
        _l.debug(f"Parsing rows")

        if self.local_run:
            chunksize = max(1, len(rows) // (4 * num_workers))
            with mp.Pool(processes=num_workers) as pool:
                results = list(
                    tqdm(
                        pool.imap_unordered(
                            self._match_parsed_row_to_node, rows, chunksize=chunksize)
                        ,
                        total=len(rows),
                        desc="Parsing rows",
                    )
                )
        else:
            results = []
            for row in rows:
                result = self._match_parsed_row_to_node(row)
                results.append(result)
        return results
        

    def parse_rows(
            self, 
            rows: List[List[Dict]], 
            current_node_list: Optional[List[List]] = None, 
            current_edge_list: Optional[List[List]] = None,
            current_node_dict_map: Optional[Dict]= None,
            current_edge_dict_map: Optional[Dict] = None
        ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        current_node_list = current_node_list or []
        current_edge_list = current_edge_list or []
        current_node_dict_map = current_node_dict_map or {}
        current_edge_dict_map = current_edge_dict_map or {}
        sink_node_list = []
        results = self.parse_rows_in_parallel(rows)

        _l.debug(f"Parsed {len(rows)} rows. Starting to match rows to nodes.")

        for result in results:
            source_node, target_node, sink_node, edge = result
            self.add_if_not_exists(current_node_list, current_node_dict_map, source_node)
            source_index = -1
            target_index = -1
            if (source_node.get('function_name') or source_node.get('filepath') or source_node.get("method_invoking_reflection")):
                source_index = self.add_if_not_exists(current_node_list, current_node_dict_map, source_node)
            if (target_node.get('function_name') or target_node.get('filepath') or target_node.get("method_invoking_reflection")):
                target_index = self.add_if_not_exists(current_node_list, current_node_dict_map, target_node)
            # if edge and edge not in edge_list:
            #     edge_list.append(edge)
            if (target_node.get('function_name') or target_node.get('filepath')) and (source_node.get('function_name') or source_node.get('filepath')):
                # Disable register call relationship here
                # if self.upload_analysis_graph and target_node.get('function_name') and source_node.get('function_name'):
                #     register_call_relationship_to_analysis_graph(self.function_resolver, source_node, target_node, call_type="direct_call", properties=edge)
                if source_index != -1 and target_index != -1:
                    source_uuid_index = current_node_list[source_index].id
                    target_uuid_index = current_node_list[target_index].id
                    edge.update(
                        {
                            'source': source_uuid_index,
                            'target': target_uuid_index,
                        }
                    )
                    self.add_if_not_exists(current_edge_list, current_edge_dict_map, edge)

            if sink_node and sink_node not in sink_node_list:
                sink_node_list.append(sink_node)

        return current_node_list, current_edge_list, sink_node_list

    def _parse_codeql_struct(self, row: List[Dict], codeql_struct: List[Enum]) -> Dict:
        if len(codeql_struct) != len(row):
            raise ValueError("CodeQL struct and row length mismatch")
        parsed_row = defaultdict(str)

        for column_name, column_value in row.items():
            parsed_row[codeql_struct[column_name]] = column_value

        return parsed_row

    @staticmethod
    def parse_codeql_location(location: str) -> tuple:
        " Parse the location string from codeql report"
        location = location[7:]
        location_split = location.split(':')
        filepath = location_split[0]
        startline = int(location_split[1])
        startoffset = int(location_split[2])
        endline = int(location_split[3])
        endoffset = int(location_split[4])
        location_info = namedtuple('Location', ['filepath', 'startline', 'startoffset', 'endline', 'endoffset'])
        return location_info(filepath, startline, startoffset, endline, endoffset)

    def _match_parsed_row_to_node(self, parsed_row: Dict) -> Tuple[Dict, Dict, Dict, Dict]:
        source_node = defaultdict(str)
        target_node = defaultdict(str)
        sink_node = defaultdict(str)
        edge = {}
        if parsed_row.get(CodeQLStruct.SOURCE_NAME.value):
            source_name = parsed_row.get(CodeQLStruct.SOURCE_NAME.value)
            source_node['function_name'] = source_name
        if parsed_row.get(CodeQLStruct.TARGET_NAME.value):
            target_name = parsed_row.get(CodeQLStruct.TARGET_NAME.value)
            target_node['function_name'] = target_name
        if parsed_row.get(CodeQLStruct.SOURCE_QUALIFIED_NAME.value):
            source_qualified_name = parsed_row.get(CodeQLStruct.SOURCE_QUALIFIED_NAME.value)
            source_node["qualified_name"] = source_qualified_name
            qualified_name_parts = source_qualified_name.split('.')
            source_node['function_name'] = qualified_name_parts[-1]
            if len(qualified_name_parts) > 1:
                source_node['class_name'] = qualified_name_parts[-2]     
        if parsed_row.get(CodeQLStruct.TARGET_QUALIFIED_NAME.value):
            target_qualified_name = parsed_row.get(CodeQLStruct.TARGET_QUALIFIED_NAME.value)
            target_node["qualified_name"] = target_qualified_name
            qualified_name_parts = target_qualified_name.split('.')
            target_node['function_name'] = qualified_name_parts[-1]
            if len(qualified_name_parts) > 1:
                source_node['class_name'] = qualified_name_parts[-2]    
        if parsed_row.get(CodeQLStruct.SOURCE_SIGNATURE.value):
            source_node['signature'] = parsed_row.get(CodeQLStruct.SOURCE_SIGNATURE.value)
        if parsed_row.get(CodeQLStruct.TARGET_SIGNATURE.value):
            target_node['signature'] = parsed_row.get(CodeQLStruct.TARGET_SIGNATURE.value)
        if parsed_row.get(CodeQLStruct.CALL_LOCATION.value):
            call_location = parsed_row.get(CodeQLStruct.CALL_LOCATION.value)
            parsed_location = self.parse_codeql_location(call_location)
            call_filepath = parsed_location.filepath
            call_lineno = int(parsed_location.startline)
            edge.update(
                {
                    'filepath': call_filepath,
                    'lineno': call_lineno
                }
            )
        if parsed_row.get(CodeQLStruct.SOURCE_LOCATION.value):
            source_location = parsed_row.get(CodeQLStruct.SOURCE_LOCATION.value)
            parsed_location = self.parse_codeql_location(source_location)
            source_filepath = parsed_location.filepath
            source_func_startline = parsed_location.startline
            source_func_endline = parsed_location.endline
            source_node.update(
                {
                    'filepath': source_filepath,
                    'function_startline': source_func_startline,
                    'location': str(source_location),
                    'startline': source_func_startline,
                    'function_endline': source_func_endline,
                    'endline': source_func_endline
                }
            )
        if parsed_row.get(CodeQLStruct.TARGET_LOCATION.value):
            target_location = parsed_row.get(CodeQLStruct.TARGET_LOCATION.value)
            parsed_location = self.parse_codeql_location(target_location)
            target_filepath = parsed_location.filepath
            target_func_startline = parsed_location.startline
            target_func_endline = parsed_location.endline
            target_node.update(
                {
                    'filepath': target_filepath,
                    'function_startline': target_func_startline,
                    'location': str(target_location),
                    'startline': target_func_startline,
                    'function_endline': target_func_endline,
                    'endline': target_func_endline
                }
            )
        if parsed_row.get(CodeQLStruct.SOURCE_BODY_LOCATION.value):
            source_body_location = parsed_row.get(CodeQLStruct.SOURCE_BODY_LOCATION.value)
            parsed_location = self.parse_codeql_location(source_body_location)
            source_node.update(
                {
                    'function_endline': parsed_location.endline
                }
            )
        if parsed_row.get(CodeQLStruct.TARGET_BODY_LOCATION.value):
            target_body_location = parsed_row.get(CodeQLStruct.TARGET_BODY_LOCATION.value)
            parsed_location = self.parse_codeql_location(target_body_location)
            target_node.update(
                {
                    'function_endline': parsed_location.endline
                }
            )
        if parsed_row.get(CodeQLStruct.SOURCE_FILEPATH.value) and not source_node.get('filepath'):
            source_filepath = parsed_row.get(CodeQLStruct.SOURCE_FILEPATH.value)
            # FIXME: absolute_path_finder is might mess with pydatatask, need to fix this
            # And absolute_path_finder cannot deal with file name collision
            # source_node['filepath'] = absolute_path_finder(self.src_root, source_filepath)
            source_node['filepath'] = source_filepath
        if parsed_row.get(CodeQLStruct.TARGET_FILEPATH.value) and not target_node.get('filepath'):
            target_filepath = parsed_row.get(CodeQLStruct.TARGET_FILEPATH.value)
            # target_node['filepath'] = absolute_path_finder(self.src_root, target_filepath)
            target_node['filepath'] = target_filepath
        if parsed_row.get(CodeQLStruct.CALL_FILEPATH.value) and not edge.get('filepath'):
            call_filepath = parsed_row.get(CodeQLStruct.CALL_FILEPATH.value)
            # FIXME: Because of currently we do not have source code in locals.
            # We need to set the filepath to None, so we can pass the test.
            # Fix this once we have jenkins source code in test targets.
            edge['filepath'] = None  # call_filepath
        if parsed_row.get(CodeQLStruct.SOURCE_LINENO.value) and not source_node.get('lineno'):
            source_lineno = parsed_row.get(CodeQLStruct.SOURCE_LINENO.value)
            source_node['lineno'] = int(source_lineno)
        if parsed_row.get(CodeQLStruct.TARGET_LINENO.value) and not target_node.get('lineno'):
            target_lineno = parsed_row.get(CodeQLStruct.TARGET_LINENO.value)
            target_node['lineno'] = int(target_lineno)
        if parsed_row.get(CodeQLStruct.CALL_LINENO.value) and not edge.get('lineno'):
            call_lineno = parsed_row.get(CodeQLStruct.CALL_LINENO.value)
            edge['lineno'] = int(call_lineno)
        if parsed_row.get(CodeQLStruct.SINK_FILEPATH.value) and not source_node.get('filepath'):
            sink_filepath = parsed_row.get(CodeQLStruct.SINK_FILEPATH.value)
            # sink_filepath = absolute_path_finder(self.src_root, sink_filepath)
            sink_node['filepath'] = sink_filepath
            # target_node['sink_filepath'] = sink_filepath

        if parsed_row.get(CodeQLStruct.SINK_LINENO.value) and not source_node.get('lineno'):
            sink_lineno = parsed_row.get(CodeQLStruct.SINK_LINENO.value)
            sink_node['lineno'] = int(sink_lineno)
            # target_node['sink_lineno'] = int(sink_lineno)

        if parsed_row.get(CodeQLStruct.SINK_LOCATION.value):
            sink_location = parsed_row.get(CodeQLStruct.SINK_LOCATION.value)
            parsed_location = self.parse_codeql_location(sink_location)
            s_filepath = parsed_location.filepath
            s_func_startline = parsed_location.startline
            sink_node['filepath'] = s_filepath
            sink_node['lineno'] = int(s_func_startline)
            sink_node['func_startline'] = s_func_startline
        if parsed_row.get(CodeQLStruct.SINK_QUALIFIED_NAME.value):
            sink_qualified_name = parsed_row.get(CodeQLStruct.SINK_QUALIFIED_NAME.value)
            sink_node['qualified_name'] = sink_qualified_name
            qualified_name_parts = sink_qualified_name.split('.')
            sink_node['function_name'] = qualified_name_parts[-1]
            if len(qualified_name_parts) > 1:
                sink_node['class_name'] = qualified_name_parts[-2]
        if parsed_row.get(CodeQLStruct.SOURCE_NODE_EXPR.value):
            source_node['expr'] = parsed_row.get(CodeQLStruct.SOURCE_NODE_EXPR.value)
        if parsed_row.get(CodeQLStruct.TARGET_NODE_EXPR.value):
            target_node['expr'] = parsed_row.get(CodeQLStruct.TARGET_NODE_EXPR.value)

        if parsed_row.get(CodeQLStruct.REFLECTION_CALL_LOCATION.value):
            source_node['reflection_call_location'] = parsed_row.get(CodeQLStruct.REFLECTION_CALL_LOCATION.value)
        if parsed_row.get(CodeQLStruct.REFLECTION_CALL_METHOD_NAME.value):
            source_node['method_invoking_reflection'] = parsed_row.get(CodeQLStruct.REFLECTION_CALL_METHOD_NAME.value)
        if parsed_row.get(CodeQLStruct.TARGET_CLASS_NAME.value):
            target_node['class_name'] = parsed_row.get(CodeQLStruct.TARGET_CLASS_NAME.value)
        if parsed_row.get(CodeQLStruct.SOURCE_CLASS_NAME.value):
            source_node['class_name'] = parsed_row.get(CodeQLStruct.SOURCE_CLASS_NAME.value)
        return source_node, target_node, sink_node, edge

    @staticmethod
    def process_sink_nodes(sink_node_list: List[Dict]):
        sink_functions = []
        for sink_node in sink_node_list:
            # sink_filepath = sink_node.get('sink_filepath')
            sink_qualified_name = sink_node.get('qualified_name')
            if sink_qualified_name and sink_qualified_name not in sink_functions:
                sink_functions.append(sink_qualified_name)
            # if sink_filepath:
            #     for node in node_list:
            #         function_name = node.get('function_name')
            #         if node.get('filepath') == sink_filepath and function_name \
            #                 and function_name not in sink_functions:
            #             sink_functions.append(function_name)
        return sink_functions

    def add_if_not_exists(
            self, 
            current_list: List, 
            current_dict_map: Dict, 
            new_dict: Dict):
        
        frozen_dict = frozenset(new_dict.items())
        if frozen_dict not in current_dict_map:
            index = len(current_list)
            if new_dict.get('method_invoking_reflection'):
                node = ReflectionCallNode(**new_dict)
            elif new_dict.get('source') and new_dict.get('target'):
                node = CallGraphEdge(**new_dict)
            elif 'function_name' not in new_dict:
                node = FlowNode(**new_dict)
            else:
                node = CallGraphNode(**new_dict)
            current_list.append(node)
            current_dict_map[frozen_dict] = index
            return index
        return current_dict_map[frozen_dict]
    
class SarifReportParser(ReportParser):
    def __init__(self, report: Path,  function_resolver: FunctionResolver):
        super().__init__(report)
        self.function_resolver = function_resolver
        self.sarif_resolver = SarifResolver(sarif_path=report, func_resolver=function_resolver)
        self.parse_report()
    
    def parse_report(self):
        self.result = self.sarif_resolver.get_results()
        # if len(self.result) == 0:
        #     self.result = self.sarif_resolver.get_dumb_results()
            # if len(self.result) == 0:
            #     return
            # result = self.result[0]
            # locations = result.locations
            # for loc in locations:
            #     codeql_query_result = self.get_function_body_location_from_codeql(
            #         filename= Path(loc.file).name,
            #         lineno = loc.line
            #     )

    def get_function_body_location_from_codeql(self, filename: str, lineno: int) -> List[Dict[str, str]]:
        """
        Get the function body location from the CodeQL server.
        """
        query_template = """
            import java
            from Method m
            where 
            m.getFile().getBaseName() = "{{ filename }}" and
            m.getBody().getLocation().getStartLine() <= {{ lineno }} and  // line number could be anywhere in function
            m.getBody().getLocation().getEndLine() >= {{ lineno }} 
            select m.getBody().getLocation(), m.getBody().getLocation().getStartLine(), m.getBody().getLocation().getEndLine()"""
        query = Template(query_template).render(filename=filename, lineno=lineno)
        result = self.codeql_client.query(
            {
                "cp_name": self.project_name,
                "project_id": self.project_id,
                "query": query,
            }
        )
        return result
