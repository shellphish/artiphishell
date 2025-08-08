from neomodel import StructuredNode, StructuredRel, StringProperty, IntegerProperty, RelationshipTo, RelationshipFrom
from analysis_graph.models import HarnessNode

class CoveredFunctionLine(HarnessNode):
    identifier = StringProperty(required=True, unique_index=True)
    function_index_key = StringProperty(required=True)
    line_number = IntegerProperty(required=True)

    containing_function = RelationshipFrom('CFGFunction', 'CONTAINS_LINE')
    covering_harness_inputs = RelationshipFrom('HarnessInputNode', 'COVERS')

from analysis_graph.models.harness_inputs import HarnessInputNode
from analysis_graph.models.cfg import CFGFunction, CFGGlobalVariable
