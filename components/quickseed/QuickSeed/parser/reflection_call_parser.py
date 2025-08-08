from enum import Enum
from pathlib import Path
from typing import List, Dict

import yaml
from QuickSeed.data import ReflectionCallNode
from typing_extensions import override

from .graph_parser import GraphParser
from .report_parser import CodeQLStruct
from .report_parser import ReportParser


class ReflectionParser(GraphParser):
    def __init__(self, report_parser: ReportParser):
        self.report_parser = report_parser
        self.reflection_call_list = []
        self.methods_invoking_reflection = []
        self.parse()

    def _parse(self):
        reflection_nodes = self.report_parser.other_nodes
        for node in reflection_nodes:
            # if not node_dict.get('method_invoking_reflection'):
            #     continue
            # reflection_call_node = ReflectionCallNode(**node_dict)

            self.reflection_call_list.append(node)
            self.methods_invoking_reflection.append(node.method_invoking_reflection)
