
import hashlib
from neomodel import StructuredNode, StringProperty, StringProperty, RelationshipTo, RelationshipFrom

class SARIFreport(StructuredNode):
    """
    Represents a SARIF report.
    """
    # The SARIF report ID (as per pdt)
    sarif_uid = StringProperty(unique_index=True)

    # This is either "injected" or "generated"
    sarif_type = StringProperty()

    # The SARIF report content
    sarif_content = StringProperty()

    # The SARIF report connects to all the CFGFunction nodes
    # that are covered by the report
    covered_functions = RelationshipTo('CFGFunction', 'COVERS')

    pov_input = RelationshipFrom('HarnessInputNode', 'CRASHED_BY')
    
    # The SARIF report might connect to a Patch node
    # if the report was generated from a patch
    #from_patch = RelationshipFrom('Patch', 'GENERATED_FROM')
    
    # The SARIF report might connect to a Patch node
    # if we generated a patch from the report
    #generated_patch = RelationshipTo('Patch', 'GENERATES')

    @classmethod
    def create_node(cls, sarif_uid: str=None, sarif_type: str=None, sarif_content: str=None):
        return cls.get_or_create({
            'sarif_uid': sarif_uid,
            'sarif_type': sarif_type,
            'sarif_content': sarif_content
        })[0]

    @classmethod
    def get_node_or_none(cls, sarif_uid: str):
        """
        Get a SARIF report node by its ID.
        :param sarif_uid: The ID of the SARIF report.
        :return: A SARIFreport object.
        """
        try:
            return cls.nodes.filter(sarif_uid=sarif_uid).first()
        except Exception as e:
            return None