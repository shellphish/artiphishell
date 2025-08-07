import json
import os
from pathlib import Path

from tqdm import tqdm
from ..import settings

from ..models.jenkins_security_advisory import JenkinsAdvisory
from ..models.jenkins_test import JenkinsTest
from ..node_update_hooks import node_updated

MY_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
DOWNLOAD_DIR = (MY_DIR / '..' / '..' / '..' / 'download').resolve()


def import_jenkins_tests():
    with open(str(DOWNLOAD_DIR / 'jenkins-tests-2.446.json'), 'r') as f:
        j = json.load(f)
    for m in tqdm(list(j)):
        jenkins_test = JenkinsTest.get_or_create({
            'class_name': m['className'],
            'method_signature': m['methodSignature'],
            'method_source': m['methodSource']
        })[0]
        if 'advisory' in m and m['advisory'] != 'XXX' and 'advisory'.startswith('SECURITY-'):
            advisory_id = int(m['advisory'].split('-')[1])

            jenkins_test.jenkins_advisory.connect(JenkinsAdvisory.get_or_create({
                'advisory_name': m['advisory'],
                'advisory_id': advisory_id
            })[0])
        node_updated(jenkins_test).save()


def main():
    import_jenkins_tests()
