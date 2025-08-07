import csv
import glob
import json
import os
from pathlib import Path

import tqdm

import pandas as pd

import traceback

from ..import settings
from ..node_update_hooks import node_updated
from ..models.cve import Assigner, Product, CVE, CWE, parse_cve_record_v5_json, parse_cwe_record
from ..models.git_repo import Commit
from ..models.jenkins_security_advisory import JenkinsAdvisory


from multiprocessing import Pool

MY_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
DOWNLOAD_DIR = (MY_DIR / '..' / '..' / '..' / 'download').resolve()

def import_cwe_data():
    print('Importing CWEs')

    with open(str(DOWNLOAD_DIR / '1425.csv'), 'r') as f:
        # parse the CSV file with the library
        reader = csv.DictReader(f)
        for row in tqdm.tqdm(list(reader)):
            parse_cwe_record(row).save()

def import_cve_json(path, filter_criteria='jenkins'):
    with open(path) as json_file:
        data = json.load(json_file)

    cve_metadata = data['cveMetadata']
    cve_id = cve_metadata['cveId']
    if cve_metadata['state'] == 'REJECTED':
        return None

    if isinstance(filter_criteria, str):
        if filter_criteria not in str(data).lower():
            return None

    elif isinstance(filter_criteria, list):
        if cve_id not in filter_criteria:
            return None

    try:
        parse_cve_record_v5_json(data).save()
    except:
        print(f'Error processing: {path}')
        traceback.print_exc()
        return None

def import_cve_data():
    print('Importing CVEs')
    cves = glob.glob(str(DOWNLOAD_DIR/ 'cvelistV5/cves/*/*/*.json'))

    # pool = Pool(8)

    # for _ in tqdm.tqdm(pool.imap_unordered(import_cve_json, cves), total=len(cves)):
        # pass

    for cve in tqdm.tqdm(cves):
        import_cve_json(cve, 'jenkins')

def import_kernel_cves():
    print('Importing Kernel CVEs')

    cves = glob.glob(str(DOWNLOAD_DIR/ 'cvelistV5/cves/*/*/*.json'))

    # cloned from https://github.com/shellphish-support-syndicate/kernel_cve_dataset
    dataset_df = pd.read_csv(os.path.join(DOWNLOAD_DIR, 'kernel_cve_dataset', 'final_kernel_cves.csv'))

    kernel_cve_ids = dataset_df['cve_id'].to_list()

    for cve in tqdm.tqdm(cves):
        import_cve_json(cve, kernel_cve_ids)


def main():
    # Neo4j connection details
    import_cwe_data()

    # if settings.TARGET_REPO == settings.TargetRepos.LINUX:
    #     import_kernel_cves()
    
    # elif settings.TARGET_REPO == settings.TargetRepos.JENKINS:
    #     import_cve_data()

