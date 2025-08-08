from datetime import datetime
from neomodel import StructuredNode, DateTimeProperty, StructuredRel, StringProperty, IntegerProperty, RelationshipTo, RelationshipFrom, JSONProperty
import pytz



class DynamicallyObservedIndirectCall(StructuredNode):
    identifier = StringProperty(unique_index=True)

    caller = RelationshipFrom('CFGFunction', 'CALLER')
    callee = RelationshipTo('CFGFunction', 'CALLEE')

    triggering_harness_input = RelationshipTo('HarnessInputNode', 'TRIGGERED_BY')
    triggering_grammar = RelationshipTo('Grammar', 'TRIGGERED_BY')

class DynamicRelationProperty(StructuredRel):
    properties = JSONProperty()

class ReferenceProperty(StructuredRel):
    ref = StringProperty(required=False)

class CWEVulnerability(StructuredNode):
    """CWE vulnerability with rule info"""
    rule_id = StringProperty(unique_index=True, required=True)  # e.g., "java/zipslip"
    cwe_tags = JSONProperty()  # list of CWE tags
    description = StringProperty()  # brief vulnerability description
    level = StringProperty()  # severity level (e.g., "error", "warning")
    security_severity = StringProperty()  # security severity score

class CWEVulnerabilityMetadata(StructuredRel):
    """Properties for CWE vulnerability relationships - contains location info"""
    line_number = IntegerProperty()

    # Store as JSON to support nested list structure: [["func1", "func2"], ["func3"]]
    codeflow_functions = JSONProperty()  # List of lists containing function keyindices for each codeflow

    # Store related location function keyindices as a JSON list
    related_locations_functions = JSONProperty()  # List of function keyindices for related locations

class CFGFunction(StructuredNode):
    identifier = StringProperty(unique_index=True)
    created_at = DateTimeProperty(default=lambda: datetime.now(pytz.utc))
    function_name = StringProperty()
    function_signature = StringProperty()
    filename = StringProperty()
    filepath = StringProperty()

    start_line = IntegerProperty()
    end_line = IntegerProperty()
    start_col = IntegerProperty()
    end_col = IntegerProperty()
    start_byte = IntegerProperty()
    end_byte = IntegerProperty()
    code = StringProperty()

    first_discovered = IntegerProperty()  # timestamp of first discovery

    direct_call = RelationshipTo('CFGFunction', 'DIRECTLY_CALLS',model=DynamicRelationProperty)

    # an indirect call that may be called (e.g. based on the signature it *could* be called, but we have not seen it yet)
    may_indirect_call = RelationshipTo('CFGFunction', 'MAYBE_INDIRECT_CALLS',model=DynamicRelationProperty)

    # an indirect call that must be called (e.g. we have seen it during dynamic analysis)
    guaranteed_indirect_call = RelationshipTo('CFGFunction', 'GUARANTEED_INDIRECT_CALLS',model=DynamicRelationProperty)

    # a reflected call that may be called (e.g. based on the signature it *could* be called, but we have not seen it yet)
    may_reflected_call = RelationshipTo('CFGFunction', 'MAYBE_REFLECTED_CALLS', model=DynamicRelationProperty)
    # a reflected call that must be called (e.g. we have seen it during dynamic analysis)
    must_reflected_cal = RelationshipTo('CFGFunction', 'MUST_REFLECTED_CALLS', model=DynamicRelationProperty)

    takes_pointer_of_function = RelationshipTo('CFGFunction', 'TAKES_POINTER_OF', model=ReferenceProperty)
    takes_pointer_of_global = RelationshipTo('CFGGlobalVariable', 'TAKES_POINTER_OF', model=ReferenceProperty)

    covered_lines = RelationshipTo('CoveredFunctionLine', 'CONTAINS_LINE')
    covering_harness_inputs = RelationshipFrom('HarnessInputNode', 'COVERS')
    covering_grammars = RelationshipFrom('Grammar', 'COVERS')

    # CWE vulnerability relationship - from function to vulnerability with location info on relationship
    has_cwe_vulnerability = RelationshipTo('CWEVulnerability', 'HAS_CWE_VULNERABILITY', model=CWEVulnerabilityMetadata)

class CFGGlobalVariable(StructuredNode):
    identifier = StringProperty(unique_index=True)

    takes_pointer_of_function = RelationshipTo('CFGFunction', 'TAKES_POINTER_OF', model=ReferenceProperty)
    takes_pointer_of_global = RelationshipTo('CFGGlobalVariable', 'TAKES_POINTER_OF', model=ReferenceProperty)


class DeltaDiffMode(StructuredNode):
    project_id = StringProperty(unique_index=True, required=True) # this is allowed to be unique_index since there's only a single diff mode per project
    git_diff = StringProperty(required=True)
    boundary_change = RelationshipTo('CFGFunction', 'BOUNDARY_CHANGE')
    function_change = RelationshipTo('CFGFunction', 'FUNCTION_CHANGE')

from analysis_graph.models.harness_inputs import HarnessInputNode
from analysis_graph.models.coverage import CoveredFunctionLine
from analysis_graph.models.grammars import Grammar
