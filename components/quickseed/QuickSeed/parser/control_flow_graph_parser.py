import logging
from enum import Enum
from pathlib import Path
from typing import List, Tuple, Dict, Optional

import networkx as nx
from QuickSeed.data.graph import ControlFlowNode, ControlFlowEdge
from QuickSeed.parser import GraphParser
from typing_extensions import override

from .report_parser import CodeQLStruct

_l = logging.getLogger(__name__)


class ControlFlowGraphParser(GraphParser):
    def __init__(self, cp_root: Path, codeql_report: Path, record_struct: List[Enum]):
        super().__init__(cp_root, codeql_report, record_struct)
        self.parse()
        self.nx_graph = self.to_networkx()
        self.contract_graph = None

    def parse(self):
        codeql_rows = self.report_data.get("#select").get("tuples")
        for row in codeql_rows:
            parsed_row = self._parse_codeql_struct(row)
            source_node, target_node, edge = self._match_parsed_row_to_node(parsed_row)
            source_node = self._construct_and_update_node_list(source_node)
            target_node = self._construct_and_update_node_list(target_node)
            edge = self._construct_and_update_edge_list(edge, source_node, target_node)

        self._update_adjacent_nodes()

    @override
    def _construct_and_update_node_list(self, node: Dict):
        existing_node = self._find_node(node)
        if existing_node:
            return existing_node
        else:
            node['id'] = self.count
            self.count += 1
            _l.debug(f'Node is {node}')
            node = ControlFlowNode(**node)
            self.nodes.append(node)
            return node

    @override
    def _construct_and_update_edge_list(
            self,
            edge: Dict,
            source_node: ControlFlowNode,
            target_node: ControlFlowNode,
    ) -> Optional[ControlFlowEdge]:

        edge['id'] = self.count
        edge['source'] = source_node.id
        edge['target'] = target_node.id
        existing_edge = self.find_edge(edge)
        if existing_edge:
            return existing_edge
        else:
            self.count += 1
            edge = ControlFlowEdge(**edge)
            self.edges.append(edge)
            return edge

    @override
    def _find_node(self, node: Dict) -> Optional[ControlFlowNode]:
        for n in self.nodes:
            if n.expr == node['expr'] and n.location == node['location']:
                return n
        return None

    def to_networkx(self) -> nx.DiGraph:
        _l.debug("Converting graph to networkx")
        G = nx.DiGraph()
        for node in self.nodes:
            G.add_node(
                node.id,
                expr=node.expr,
            )
        for edge in self.edges:
            G.add_edge(
                edge.source,
                edge.target,
                label=edge.label,
            )
        return G

    def _all_locations(self) -> List[Tuple[int, int]]:
        locations = []
        for node in self.nodes:
            if (node.startline, node.endline) not in locations:
                locations.append((node.startline, node.endline))
        return locations

    def merge_nodes_with_same_location(self):
        # CodeQL gives us the minimal node, which we should merge based on the location
        # We should merge nodes with the same startline and endline to reduce the node number
        locations = self._all_locations()
        new_nodes = []
        new_edges = []
        for location in locations:
            nodes = self._find_all_nodes_with_locaiton(location)
            merged_node = self._merge_nodes(nodes)
            new_nodes.append(merged_node)
        node_id = [n.id for n in new_nodes]
        for node in new_nodes:
            for n in node.next_nodes:
                if n in node_id:
                    new_edges.append(ControlFlowEdge(id=self.count, source=node.id, target=n))
                    self.count += 1
        self.nodes = new_nodes
        self.edges = new_edges
        for node in self.nodes:
            _l.debug(f"Merged Node is {node}")
        self.nx_graph = self.to_networkx()

    def _merge_nodes(self, nodes) -> ControlFlowNode:
        # TODO: The expression we always take the first one, and we will base on the expression to find the 
        # branch condition. But this will fail if `if ...`
        node = nodes[0]
        if len(nodes) == 1:
            return node
        for n in nodes[1:]:
            for i in n.next_nodes:
                if i not in node.next_nodes:
                    node.next_nodes.append(i)
            for i in n.previous_nodes:
                if i not in node.previous_nodes:
                    node.previous_nodes.append(i)
        return node

    def _find_all_nodes_with_locaiton(self, location: Tuple[int, int]) -> List[ControlFlowNode]:
        nodes = []
        for node in self.nodes:
            if node.startline == location[0] and node.endline == location[1]:
                nodes.append(node)
        return nodes

    def _find_root(self) -> List[ControlFlowNode]:
        root_nodes = []
        for node in self.nodes:
            if node.previous_nodes == []:
                root_nodes.append(node)
        return root_nodes
