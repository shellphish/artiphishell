from neomodel import StructuredNode, StringProperty, RelationshipTo


class JenkinsTest(StructuredNode):
    method_signature = StringProperty(unique_index=True, required=True)
    class_name = StringProperty(required=True)
    method_source = StringProperty(required=True)
    jenkins_advisory = RelationshipTo('JenkinsAdvisory', 'JENKINS_ADVISORY')
