import git
import os
import json
import requests
from unidiff import PatchSet
import time
import difflib
import traceback

import requests

import json
from tqdm import tqdm
import pandas as pd


from ..clang_utils import get_functions_in_commit_file
from ..clients.parser_api_client import ParserAPI
from ..settings import LINUX_KERNEL_FILE_SUFFICES



def process_single_cve(repo, fix_sha, vuln_sha):

    cve_info = {}

    cve_info['fix_commit_sha'] = str(fix_sha)

    commit = repo.commit(fix_sha)

    cve_info['vuln_commit_sha'] = vuln_sha

    diff = repo.git.diff(vuln_sha, fix_sha)
    patch_set = PatchSet(diff)
    patched_files = [f.path for f in patch_set.modified_files if f.path.split('.')[-1] in LINUX_KERNEL_FILE_SUFFICES]

    cve_info['patched_files'] = patched_files
    cve_info['file_diffs'] = [str(f) for f in patch_set.modified_files if f.path.split('.')[-1] in LINUX_KERNEL_FILE_SUFFICES]

    cve_info['patched_funcs'] = [[] for f in patched_files]
    cve_info['before_funcs'] = [[] for f in patched_files]
    cve_info['after_funcs'] = [[] for f in patched_files]
    cve_info['func_diffs'] = [[] for f in patched_files]

    for ii, fpath in enumerate(patched_files):
        before = get_functions_in_commit_file(repo, vuln_sha, fpath)
        after = get_functions_in_commit_file(repo, fix_sha, fpath)
        patched_funcs = ParserAPI.find_patched_funcs(before, after)
        for func in patched_funcs:
            cve_info['patched_funcs'][ii].append(func)
            cve_info['before_funcs'][ii].append(before[func])
            cve_info['after_funcs'][ii].append(after[func])
            func_diff = difflib.unified_diff(before[func]['src'].split('\n'), after[func]['src'].split('\n'), fromfile='before_func', tofile='after_func')
            func_diff = '\n'.join(list(iter(func_diff)))
            cve_info['func_diffs'][ii].append(func_diff)

    return cve_info

def main():

    import argparse

    parser = argparse.ArgumentParser(description='Prepare the syzbot crashes dataset')
    parser.add_argument('git_repo', help='Path to the git repo of Linux Kernel to import')
    parser.add_argument('cves_dataset', help='Path to the kernel CVEs dataset (cloned from https://github.com/shellphish-support-syndicate/kernel_cve_dataset)')
    parser.add_argument('save_file', help='Path to the output file')

    args = parser.parse_args()

    repo = git.Repo(args.git_repo)

    dataset_df = pd.read_csv(args.cves_dataset)
    
    print(f'{len(dataset_df)} CVEs found')

    cve_info = []
    for ii in tqdm(range(len(dataset_df))):

        row = dataset_df.iloc[ii]

        cve_id = row['cve_id']
        cwe_id = row['cwe']
        description = row['nvd_text']

        fixing_commit = row['fix_commit_id']
        before_commit = row['project_before']

        try:
            cur_cve_info = process_single_cve(repo, fixing_commit, before_commit)
        except:
            print(f'Error processing row: {ii} - {cve_id}')
            traceback.print_exc()
            continue

        cur_cve_info.update({'cve_id':cve_id, 'description': description, 'cwe_id': cwe_id})

        cve_info.append(cur_cve_info)

    with open(args.save_file, 'w') as f:
        f.write(json.dumps(cve_info, indent=4))


# kb_prepare_kernelcves_dataset download/linux/ download/kernel_cve_dataset/final_kernel_cves.csv download/kernel_cves_prepared.json 