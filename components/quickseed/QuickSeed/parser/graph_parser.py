import logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional, Dict
from collections import defaultdict

import matplotlib.pyplot as plt
import networkx as nx

from .report_parser import ReportParser

_l = logging.getLogger(__name__)


IMPORTANT_SINKS = [
    "Runtime.exec", "ProcessBuilder.start"
]

class SINK_source(Enum):
    LLM = 'LLM'
    JAZZER = 'JAZZER'

class SAST_source(Enum):
    CodeQL = 'CodeQL'
    Joern = 'Joern'


class SinkType(Enum):
    SANITIZER = auto()
    COMMIT = auto()
    UNDEFINED = auto()


class GraphParser(ABC):
    def __init__(
            self,
            cp_root: Path,
            report_parser: ReportParser,
            language: str,
            source: Optional[List[str]] = None,
            sink: Optional[List[str]] = None
    ):
        self.cp_root = cp_root
        # self.report = report
        # self.record_struct = record_struct
        self.source = source
        self.sink = sink
        self.nodes = {}
        self.edges = {}
        self.report_parser = report_parser
        self.source_node_ids = []
        self.sink_node_ids = []
        self.sink_node_ids_by_type = defaultdict(list)
        self.language = language
        self.graph = nx.DiGraph()

    def parse(self):
        return self._parse()

    @abstractmethod
    def _parse(self):
        pass

    # @abstractmethod
    # def _update_nodes(self, *args, **kwargs):
    #     pass

    # @abstractmethod
    # def _update_edges(self, *args, **kwargs):
    #     pass

    # @abstractmethod
    # def _update_graph(self, *args, **kwargs):
    #     pass

    def visualize_graph(self, label: str):
        if not self.graph:
            _l.warning("No graph to visualize")
            return
        pos = nx.spring_layout(self.graph)

        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos, node_color='lightblue', node_size=3000, alpha=0.8)

        # Draw edges
        nx.draw_networkx_edges(self.graph, pos)

        # Create a dictionary mapping node to function name

        labels = nx.get_node_attributes(self.graph, label)

        # Draw labels
        nx.draw_networkx_labels(self.graph, pos, labels, font_size=10)

        plt.title("Graph with Function Names as Labels", fontsize=16)
        plt.axis('off')
        plt.tight_layout()
        plt.show()
        nx.draw(self.graph, with_labels=True)
        plt.show()

    @staticmethod
    def _is_valid_node(node: Dict) -> bool:
        if not node.get("function_name") or not node.get("filepath"):
            return False
        return True
