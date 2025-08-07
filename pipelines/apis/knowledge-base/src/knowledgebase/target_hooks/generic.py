
import re
from knowledgebase.models.cve import Reference
from knowledgebase.models.git_repo import Commit
from knowledgebase.models.jenkins_security_advisory import JenkinsAdvisory
from knowledgebase.node_update_hooks import node_updated, register_for_node_update


def parse_github_url(url):
    if match := re.match(r'https://github.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)', url):
        return {
            'owner': match.group(1),
            'repository': match.group(2),
            'commit': match.group(3),
        }
    elif match := re.match(r'https://github.com/([^/]+)/([^/]+)', url):
        return {
            'owner': match.group(1),
            'repository': match.group(2),
        }
    else:
        return None

@register_for_node_update(Reference)
def populate_referenced_objects(reference: Reference):
    if (repo := parse_github_url(reference.url)) and 'commit' in repo:
        # TODO: deal with this later if there's not a commit
        commit = Commit.get_or_create({'repo': repo['repository'], 'sha': repo['commit']})[0]
        reference.referenced_commit.connect(commit)
        return reference.save()

    elif (advisory := JenkinsAdvisory.from_advisory_url(reference.url)):
        reference.referenced_jenkins_advisory.connect(advisory)
        return reference.save()

    else:
        return None

@register_for_node_update(Commit)
def on_Commit_update(commit: Commit):
    if commit.message is not None and (advisory := JenkinsAdvisory.extract_from_text(commit.message)):
        advisory.referenced_by_commits.connect(commit)
        advisory.save()
        node_updated(advisory)

