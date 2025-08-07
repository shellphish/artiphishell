import git
import os
import json
import logging
import openai
import re

from unidiff import PatchSet, PatchedFile
import difflib
import traceback
import pandas as pd
from Levenshtein import distance

from tqdm.auto import tqdm
from pathlib import Path

from ..clients.embedding_api_client import EmbeddingsAPI
from ..settings import LINUX_KERNEL_FILE_SUFFICES, AUTH_KEY, DEFAULT_EMBEDDING_MODEL
from ..clang_utils import get_functions_in_commit_file
from ..clients.parser_api_client import ParserAPI


HUNK_LIMIT = 3
FILE_LIMIT = 1
FUNC_LIMIT = 1


def count_hunks(diff_text):
    # Define the regex pattern for hunk headers
    hunk_header_pattern = re.compile(r'^@@ -\d+(,\d+)? \+\d+(,\d+)? @@')
    
    # Split the diff text into lines
    lines = diff_text.split('\n')
    
    # Initialize hunk counter
    hunk_count = 0
    
    # Iterate through the lines and count hunk headers
    for line in lines:
        if hunk_header_pattern.match(line):
            hunk_count += 1
            
    return hunk_count

def get_open_ai_embeddings(code):
    client = openai.OpenAI(api_key="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")

    response = client.embeddings.create(
        input=code,
        model='-'.join(DEFAULT_EMBEDDING_MODEL.split('-')[1:])
    )

    return response.data[0].embedding

def patch_file_filter_condition(f: PatchedFile):
    if 'test' not in f.path and f.path.split('.')[-1] in LINUX_KERNEL_FILE_SUFFICES:
        return True
    else:
        return False
    

def remove_comments(code):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, code)

def generate_patch_report_from_diff(repo, patch_set, vuln_sha, fix_sha, embs_api, file_limit, function_per_file_limit, hunk_per_func_limit):

    report = {}
    patched_files =  [f.path for f in patch_set.modified_files if patch_file_filter_condition(f)]

    if len(patched_files) > file_limit or len(patched_files) < 1:
        raise RuntimeError(f"The commit fixed {len(patched_files)} valid files.")
    

    report['patched_files'] = patched_files
    report['file_diffs'] = [str(f) for f in patch_set.modified_files if patch_file_filter_condition(f)]

    report['patched_funcs'] = [[] for f in patched_files]
    report['before_funcs'] = [[] for f in patched_files]
    report['after_funcs'] = [[] for f in patched_files]
    report['func_diffs'] = [[] for f in patched_files]
    report['before_func_embs'] = [[] for f in patched_files]
    report['after_func_embs'] = [[] for f in patched_files]
    report['func_diff_embs'] = [[] for f in patched_files]
    report['edit_distances'] = [[] for f in patched_files]

    num_total_patched_func = 0

    for ii, fpath in enumerate(patched_files):
        before = get_functions_in_commit_file(repo, vuln_sha, fpath)
        after = get_functions_in_commit_file(repo, fix_sha, fpath)
        patched_funcs = ParserAPI.find_patched_funcs(before, after)

        if len(patched_funcs) > function_per_file_limit or len(patched_funcs) < 1:
            continue

        for func in patched_funcs:
            before_src = remove_comments(before[func]['src'])
            after_src = remove_comments(after[func]['src'])
            dist = distance(before_src, after_src)
            
            if dist == 0:
                continue

            func_diff = difflib.unified_diff(before_src.split('\n'), after_src.split('\n'), fromfile='before_func', tofile='after_func')
            func_diff = '\n'.join(list(iter(func_diff)))

            num_hunks = count_hunks(func_diff)

            if num_hunks > hunk_per_func_limit or num_hunks < 1:
                continue

            report['patched_funcs'][ii].append(func)
            report['before_funcs'][ii].append(before_src)
            report['after_funcs'][ii].append(after_src)
            report['func_diffs'][ii].append(func_diff)

            logging.warning(f"{fpath} - {func} - before len {len(before_src)} - after len {len(after_src)} - diff len {len(func_diff)}")

            before_embs = get_open_ai_embeddings(before_src) # embs_api.get_code_embeddings(before_src).tolist()
            after_embs = get_open_ai_embeddings(after_src) # embs_api.get_code_embeddings(after_src).tolist()
            diff_embs = get_open_ai_embeddings(func_diff) # embs_api.get_code_embeddings(func_diff).tolist()

            report['before_func_embs'][ii].append(before_embs)
            report['after_func_embs'][ii].append(after_embs)
            report['func_diff_embs'][ii].append(diff_embs)
            report['edit_distances'][ii].append(dist)

            num_total_patched_func += 1

    
    if num_total_patched_func == 0:
        raise RuntimeError("No valid function patches were found.")

    return report



def process_entry(entry, download_path, save_path, embs_api, patch_index):

    owner = entry["owner"]
    repo_name = entry["repo"]
    fix_sha = entry["commit_id"]
    category = entry["category"]
    cwe_id = entry["CWE_ID"]
    diff = entry["diff_code"]

    label = (category == "security")

    username = 'yigitcankaya'
    password = 'blablabla'

    github_url = f'https://{username}:{password}github.com/{owner}/{repo_name}'

    save_filename = f'{owner}XXX{repo_name}XXX{label}XXX{cwe_id}XXX{patch_index}.json'
    save_filename = os.path.join(save_path, save_filename)

    if os.path.isfile(save_filename):
        logging.warning(f'{save_filename} exists...')
        return 1

    # must exist
    project_download_path = os.path.join(download_path, repo_name)

    logging.warning(f'Processing Entry - For project: {repo_name}, from owner {owner}.')

    # download the project from github
    if not os.path.isdir(project_download_path):
        repo = git.Repo.clone_from(github_url, project_download_path)
    else:
        repo = git.Repo(project_download_path)

    vuln_sha = repo.commit(fix_sha).parents[0].hexsha

    diff_patchset = PatchSet(diff)

    full_patch_set = PatchSet(repo.git.diff(vuln_sha, fix_sha))

    if label == 0:       # regular patch  
        report = generate_patch_report_from_diff(repo, diff_patchset, vuln_sha, fix_sha, embs_api, file_limit=3, function_per_file_limit=5, hunk_per_func_limit=3)
    else:   # vulnerability patch
        report = generate_patch_report_from_diff(repo, diff_patchset, vuln_sha, fix_sha, embs_api, file_limit=1, function_per_file_limit=1, hunk_per_func_limit=3)


    with open(save_filename, 'w') as fp:
        json.dump(report, fp)

    return 1



def main():

    import argparse

    parser = argparse.ArgumentParser(description='Prepare the syzbot crashes dataset')

    #  http://beatty.unfiltered.seclab.cs.ucsb.edu:49152
    parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')
    parser.add_argument('--patch_db_path', default='./download/patch_db.json')
    parser.add_argument('--download_path', help='Path to clone oss-fuzz projects', default='/data/yigitcankaya/patchdb_projects')
    parser.add_argument('--save_path', help='Path to clone oss-fuzz projects', default='./download/patch_db_processed')

    args = parser.parse_args()

    with open(args.patch_db_path, 'r') as fp:
        patch_db = json.load(fp)

    logging.warning(f"There are {len(patch_db)} patches in the file")

    embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)

    Path(args.download_path).mkdir(parents=True, exist_ok=True)
    Path(args.save_path).mkdir(parents=True, exist_ok=True)

    succcess = 0
    for ii, patch_entry in tqdm(enumerate(patch_db[6500:])):

        logging.warning(f'Process {ii+1}/{len(patch_db)} -- success: {succcess}')
        try:
            status = process_entry(patch_entry, args.download_path, args.save_path, embs_api, ii)
            succcess += status

        except:
            logging.error(traceback.format_exc())
            continue


        # if status:
        #     break


# kb_diff_dataset http://beatty.unfiltered.seclab.cs.ucsb.edu:49152
