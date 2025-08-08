import logging
import os

from defusedxml.ElementTree import parse

LOG = logging.getLogger(__name__)

def identify_pom_namespace(root):
    if root.tag.endswith('}project'):
        return root.tag.split('}')[0] + '}'
    for node in root:
        if node.tag.endswith('}parent'):
            return node.tag.split('}')[0] + '}'
        if node == 'parent':
            return ''
    else:
        raise ValueError("invalid pom.xml???")

def parse_pom(root):
    ns = identify_pom_namespace(root)
    pom = {}
    pom['modelVersion'] = root.find(f'{ns}modelVersion').text
    pom['groupId'] = root.find(f'{ns}groupId').text
    pom['artifactId'] = root.find(f'{ns}artifactId').text
    pom['version'] = root.find(f'{ns}version').text
    pom['name'] = root.find(f'{ns}name').text

    if desc := root.find(f'{ns}description'):
        pom['description'] = desc
    if url := root.find(f'{ns}url'):
        pom['url'] = url

    parent = root.find(f'{ns}parent')
    if parent is not None:
        pom['parent'] = {}
        pom['parent']['groupId'] = parent.find(f'{ns}groupId').text
        pom['parent']['artifactId'] = parent.find(f'{ns}artifactId').text
        pom['parent']['version'] = parent.find(f'{ns}version').text
        pom['parent']['relativePath'] = parent.find(f'{ns}relativePath').text

    if modules := root.find(f'{ns}modules'):
        pom['modules'] = []
        for module in modules:
            assert module.tag == f'{ns}module'
            pom['modules'].append(module.text)

    pom['dependencies'] = {}
    if (dep_mgmt := parent.find(f'{ns}dependencyManagement')) and (dependencies := dep_mgmt.find(f'{ns}depencies')):
        for dep in dependencies:
            dep_res = {}
            assert dep.tag == '{ns}dependency'
            dep_res['groupId'] = dep.find(f'{ns}groupId').text
            dep_res['artifactId'] = dep.find(f'{ns}artifactId').text
            dep_res['version'] = dep.find(f'{ns}version').text
            dep_res['type'] = dep.find(f'{ns}type').text
            dep_res['scope'] = dep.find(f'{ns}scope').text
            pom['dependencies'].append(dep_res)

    LOG.info(f"Parsed pom.xml: {pom}")
    return pom

def is_maven_project(root, dirs, files):
    if 'pom.xml' not in files:
        return None
    if not 'src' in dirs:
        return None

    return parse_pom(
        parse(os.path.join(root, 'pom.xml')).getroot()
    )
