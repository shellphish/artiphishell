
import re
from datetime import datetime
from .git_repo import Commit
from ..node_update_hooks import node_updated
from neomodel import StructuredNode, StringProperty, IntegerProperty, RelationshipTo, RelationshipFrom, Relationship, ZeroOrMore, OneOrMore, One, DateProperty, DateTimeFormatProperty

        # TODO:
        # https://www.cloudbees.com/security-advisories/jenkins-security-advisory-2011-11-08
        # elif match := re.match(r'(http|https)://www.cloudbees.com/security-advisori/jenkins-security-advisory-(\d{4}-\d{2}-\d{2}).cb', url):
        #     # not relevant here, different advisory style/layout
        #     return None
        # elif match := re.match(r'(http|https)://www.cloudbees.com/jenkins-advisory/jenkins-security-advisory-(\d{4}-\d{2}-\d{2}).cb', url):
        #     # not relevant here, different advisory style/layout
        #     return None

class JenkinsAdvisory(StructuredNode):
    advisory_name = StringProperty(unique_index=True, required=True)
    advisory_id = IntegerProperty(unique_index=True, required=True)
    date = DateProperty()
    url = StringProperty()

    oldest_patch_commit = RelationshipTo('Commit', 'OLDEST_PATCH_COMMIT')
    vulnerable_commit = RelationshipTo('Commit', 'VULNERABLE_COMMIT')

    vulnerability_description = StringProperty()

    @staticmethod
    def from_advisory_url(url: str):
        if 'jenkins.io' not in url.lower() or 'SECURITY-' not in url.upper():
            return None

        # import ipdb; ipdb.set_trace()
        if match := re.match(r'https://www.jenkins.io/security/advisory/(\d{4}-\d{2}-\d{2})/#SECURITY-(\d+)', url):
            date_group  = match.group(1)
            advisory_id = int(match.group(2))
            return node_updated(JenkinsAdvisory.get_or_create(
                {
                    'advisory_name': f'SECURITY-{advisory_id}',
                    'advisory_id': advisory_id,
                    'date': datetime.strptime(date_group, '%Y-%m-%d'),
                    'url': url
                }
            )[0]).save()

        elif match := re.match(r'https://jenkins.io/security/advisory/(\d{4}-\d{2}-\d{2})/#SECURITY-(\d+)', url):
            date_group  = match.group(1)
            advisory_id = int(match.group(2))
            return node_updated(JenkinsAdvisory.get_or_create(
                {
                    'advisory_name': f'SECURITY-{advisory_id}',
                    'advisory_id': advisory_id,
                    'date': datetime.strptime(date_group, '%Y-%m-%d'),
                    'url': url
                }
            )[0]).save()

        else:
            assert False, f'Unknown Jenkins advisory URL format: {url}'

    @staticmethod
    def extract_from_text(text):
        if match := re.match(r'SECURITY-(\d+)', text):
            advisory_id = int(match.group(1))
            return node_updated(JenkinsAdvisory.get_or_create(
                {
                    'advisory_name': f'SECURITY-{advisory_id}',
                    'advisory_id': advisory_id,
                }
            )[0]).save()
