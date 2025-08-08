import logging
import os

from .maven import parse_pom

from defusedxml.ElementTree import parse

LOG = logging.getLogger(__name__)

def is_jenkins_root(root, dirs, files):
    if 'pom.xml' not in files:
        return None
    if not {'core', 'war', 'bom', 'cli', 'src', 'test'}.issubset(dirs):
        return None

    if not os.path.isdir(os.path.join(root, 'core/src/main/java/jenkins')):
        return None

    assert os.path.isdir(os.path.join(root, 'core/src/main/java/hudson'))

    pom = parse_pom(
        parse(os.path.join(root, 'pom.xml')).getroot()
    )
    LOG.info(f"Found Jenkins root in {root} with pom: {pom}")
    return pom



def is_jenkins_plugin(root, dirs, files):
    if 'pom.xml' not in files:
        return None

    if not os.path.isdir(os.path.join(root, 'src/main/java/io/jenkins/plugins')):
        return None

    # parse pom.xml
    pom = parse_pom(
        parse(os.path.join(root, 'pom.xml')).getroot()
    )

    if pom['groupId'] != 'io.jenkins.plugins' or pom['parent']['groupId'] != 'org.jenkins-ci.plugins':
        return None

    LOG.info(f"Found Jenkins plugin in {root} with pom: {pom}")
    return pom