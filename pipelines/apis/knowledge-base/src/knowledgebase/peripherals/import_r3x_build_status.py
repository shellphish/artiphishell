import csv
import glob
import json
import os
from pathlib import Path

import tqdm


from ..import settings
from ..node_update_hooks import node_updated
from ..models.generic import Reference
from ..models.cve import Assigner, Product, CVE, CWE, parse_cve_record_v5_json, parse_cwe_record
from ..models.git_repo import Commit
from ..models.jenkins_security_advisory import JenkinsAdvisory

MY_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
DOWNLOAD_DIR = (MY_DIR / '..' / '..' / '..' / 'download').resolve()

def import_r3x_jenkins_build_status_info():
    '''
    id,oldest_patch_commit,commit_date,vulnerable_commit,build,jdk_version
    SECURITY-3135,3059161906e63eb3be7a9f7115a70437818b9116,2023-09-08 23:50:15,30540d76d308bb8b16dfe33b2731c33900d263fd,True,openjdk-21
    SECURITY-3073,f06bb8820115996397a2e0010b003ecbf0570865,2023-09-06 07:17:31,df7c4ccda8976c06bf31b8fb9938f26fc38501ca,True,openjdk-21
    SECURITY-3072,df7c4ccda8976c06bf31b8fb9938f26fc38501ca,2023-09-06 07:17:25,4bf648811f328961627f484349d40420d169cdd0,True,openjdk-21
    '''
    # import ipdb; ipdb.set_trace()
    with open(str(DOWNLOAD_DIR / 'updated_commit_analysis.csv'), 'r') as f:
        # parse the CSV file with the library
        reader = csv.DictReader(f)
        for row in tqdm.tqdm(list(reader)):
            vuln_commit_hash = row['vulnerable_commit']
            commit = Commit.get_or_create({'repo': 'jenkins', 'sha': vuln_commit_hash})[0]
            commit.successfully_built = row['build'] == 'True'
            if row['jdk_version']:
                commit.build_jdk_version = row['jdk_version']
            node_updated(commit).save()

            jenkins_advisory = JenkinsAdvisory.get_or_create({
                'advisory_name': row['id'],
                'advisory_id': int(row['id'].split('-')[1]),
            })[0]
            jenkins_advisory.vulnerable_commit.connect(commit)
            jenkins_advisory.oldest_patch_commit.connect(Commit.get_or_create({'repo': 'jenkins', 'sha': row['oldest_patch_commit']})[0])
            node_updated(jenkins_advisory).save()


def main():
    # Neo4j connection details
    import_r3x_jenkins_build_status_info()