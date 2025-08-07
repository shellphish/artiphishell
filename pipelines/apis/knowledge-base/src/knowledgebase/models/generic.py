import re
from neomodel import StructuredNode, StringProperty, RelationshipTo, ZeroOrOne, RelationshipFrom, ZeroOrMore

from knowledgebase.node_update_hooks import node_updated, register_for_node_update
from knowledgebase.models.git_repo import Commit
from knowledgebase.models.jenkins_security_advisory import JenkinsAdvisory

class Reference(StructuredNode):
    url = StringProperty(required=True)
    referenced_jenkins_advisory = RelationshipTo('JenkinsAdvisory', 'REFERENCED_JENKINS_ADVISORY')
    referenced_commit = RelationshipTo('Commit', 'REFERENCED_COMMIT')