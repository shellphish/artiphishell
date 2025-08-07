import argparse
import os
import json
import yaml
import git
import glob
import io

import tempfile
import logging
import numpy as np
import time
import difflib
import requests

from pathlib import Path
from typing import List

import parser as java_parser

AUTH_KEY = '!!Shellphish!!'


# to fetch a file from a specific commit of the github repo
class CommitFile:
    def __init__(self, repo, commit_sha, file_path, bytes=False):
        commit = repo.commit(commit_sha)
        file = commit.tree / file_path
        with io.BytesIO(file.data_stream.read()) as f:
            cnts = f.read()
            if not bytes:
                cnts = cnts.decode('utf-8')

        self.contents = cnts
        self.extension = os.path.splitext(file_path)[1]


def get_modified_func_info(indexer_output_dir):


    all_modified_files = [fdir for fdir in glob.glob(f'{indexer_output_dir}/*/*/methods/*.json')]

    logging.info(f"Found {len(all_modified_files)} files in the clang_index_by_commit dir...")

    modified_func_metadata = {}

    for f in all_modified_files:
        with open(os.path.realpath(f), 'r') as fp:
            func_metadata = json.load(fp)
            filepath = func_metadata['filepath'] # "plugins/pipeline-util-plugin/src/main/java/io/jenkins/plugins/UtilPlug/UtilMain.java"
            funcname = func_metadata['funcname']
            code = func_metadata['code']

            commit_sha = f.split(os.sep)[-3].split('_')[1]

            key = f'{filepath}::{commit_sha}'

            if key not in modified_func_metadata:
                modified_func_metadata[key] = []

            modified_func_metadata[key].append((funcname, code))


    logging.info(modified_func_metadata.keys())

    return modified_func_metadata


def get_reverse_diff_for_funcs(modified_func_metadata, git_repos, target_dir):

    reverse_diffs = {}

    for identifier in modified_func_metadata:

        # plugins/pipeline-util-plugin/src/main/java/io/jenkins/plugins/UtilPlug/UtilMain.java
        filepath, commit_sha = identifier.split('::')

        repo_name, repo = return_repo_containing_file(filepath, git_repos)

        _filepath = os.path.relpath(filepath, repo_name)

        after_commit = repo.commit(commit_sha)

        parent_sha = after_commit.parents[0].hexsha

        cf = CommitFile(repo, parent_sha, _filepath, bytes=True)
        tf = tempfile.NamedTemporaryFile(delete=True, suffix=cf.extension)
        tf.write(cf.contents)

        info = java_parser.process_file(tf.name, target_dir)

        for mod in modified_func_metadata[identifier]:
        
            funcname, after_code = mod

            for func_info in info:
                inner_funcname = func_info["funcname"]
                if inner_funcname == funcname:
                    break

            before_code = func_info['code'] # this is supposed to be the secure code 

            if after_code == before_code:
                logging.error('Before code = After code, no diff!')
                logging.error(f'file {filepath} - func {funcname} - after {commit_sha} - before {parent_sha}')
                continue

            # CRITICAL: After -> Before will be more similar to existing vulnerability patches
            func_diff = difflib.unified_diff(after_code.split('\n'), before_code.split('\n'), fromfile='before_func', tofile='after_func')

            if funcname not in reverse_diffs:
                reverse_diffs[funcname] = []

            diff_text = '\n'.join(list(iter(func_diff)))

            reverse_diffs[funcname].append((commit_sha, diff_text))

    return reverse_diffs
 

def get_diff_score(retrieval_api_uri, diff, kb_names=['Generic_C']):

    all_sim_scores = []

    max_score = 0
    best_diff = ''
    best_funcname = ''

    for kb_name in kb_names:
        res = requests.post(f'{retrieval_api_uri}/api/funcs/closest_diff', json={
            "query": diff, # source code goes there
            "num_return": 1, # how many similar functions you're retrieving
            "auth_key": AUTH_KEY,
            "knowledge_base": kb_name
        })
        
        res = res.json()
        
        if 'result' not in res:
            print(res)
            continue
        
        res = res['result'][0] # return only one
        sim_score = res['score'] # take the average across num_avg diffs

        if sim_score > max_score:
            max_score = sim_score
            best_diff = res['code_diff']
            best_funcname = res['full_name']

    return max_score, best_diff, best_funcname, diff # return the maximum across all knowledge bases


def rank_all_diffs(reverse_diffs, retrieval_api_uri):


    res = requests.post(f'{retrieval_api_uri}/api/info/available_kbs', json={
    "auth_key": '!!Shellphish!!'
    })

    kb_names = res.json()

    func_diff_scores = {}

    for funcname in reverse_diffs:

        for commit, diff in reverse_diffs[funcname]:

            if funcname not in func_diff_scores:
                func_diff_scores[funcname] = []
            
            func_diff_scores[funcname].append((commit, *get_diff_score(retrieval_api_uri, diff, kb_names=['Generic_C'])))

    
    ind_commits = lambda fn: [x[0] for x in func_diff_scores[fn]]
    ind_scores = lambda fn: [float(x[1]) for x in func_diff_scores[fn]]
    ind_diffs = lambda fn: [x[2] for x in func_diff_scores[fn]]
    ind_funcnames = lambda fn: [x[3] for x in func_diff_scores[fn]]
    orig_diffs = lambda fn: [x[4] for x in func_diff_scores[fn]]

    funcnames = list(func_diff_scores.keys())
    
    # if the function has multiple diffs, take the max score
    func_diff_scores_aggr = np.asarray([max(ind_scores(funcname)) for funcname in funcnames])

    # descending
    sorted_indices = np.argsort(-func_diff_scores_aggr)

    ret = [funcnames[ii] for ii in sorted_indices]

    
    # ret = [
    #         {
    #         'funcname': funcnames[ii],
    #         'max_score': float(func_diff_scores_aggr[ii]),
    #         'ranking': rank+1,
    #         'total': len(sorted_indices),
    #         'func_diffs': orig_diffs(funcnames[ii]), 
    #         'commits': ind_commits(funcnames[ii]),
    #         'similar_diffs': ind_diffs(funcnames[ii]),
    #         'similar_funcs': ind_funcnames(funcnames[ii]),
    #         'scores_per_commit': ind_scores(funcnames[ii])
    #         } for rank, ii in enumerate(sorted_indices)]

    return ret

def return_repo_containing_file(full_file_name, repos):

    for repo_name, repo in repos.items():
        rel_file_name = os.path.relpath(full_file_name, repo_name)
        for entry in repo.commit().tree.traverse():
            if rel_file_name in entry.path:
                return repo_name, repo


if __name__ == '__main__':
    logging.basicConfig(level = logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--antlr4-output-by-commit", type=str, required=True, help="Output dir produced by antlr4-guy (antlr4_commit_java_parser.output_dir_java)")
    parser.add_argument("-d", "--target-dir", type=str, required=True, help="Target directory, the same project directory antlr4-guy consumes")
    parser.add_argument("-o", "--output-path", type=str, required=True, help="Output file to output the result yaml.")

    args = parser.parse_args()

    if 'RETRIEVAL_API' not in os.environ:
        logging.critical('DiffRanker::Diff ranking relies on retrieval API, RETRIEVAL_API environment key was not found.')
        raise KeyError
    
    retrieval_api_uri = os.environ['RETRIEVAL_API']

    modification_info = get_modified_func_info(args.antlr4_output_by_commit)

    nfiles = len(modification_info)
    nfuncs = sum([len(v) for v in modification_info.values()])
    
    logging.info(f"Getting the reverse diffs for function modifications for {nfiles} files and {nfuncs} functions...")

    # find all the git repositories
    git_repos_paths = java_parser.find_git_repos(os.path.join(args.target_dir, 'src'))

    git_repos = {}

    for repo_path in git_repos_paths:
        try:
            repo = git.Repo(repo_path)
            repo_name = os.path.relpath(repo_path, os.path.join(args.target_dir, 'src'))
            git_repos[repo_name] = repo
        except:
            continue
        

    logging.info(git_repos)

    start = time.time()

    reverse_diffs = get_reverse_diff_for_funcs(modification_info, git_repos, args.target_dir)

    nunique_funcs = len(reverse_diffs)
    ntotal = sum([len(v) for v in modification_info.values()])

    logging.info(f"Reverse diffs found for function modifications for {nunique_funcs} functions ({list(reverse_diffs.keys())}) and {ntotal} total changes...")

    logging.info(f"Reverse diffing took {time.time() - start} seconds...")

    start = time.time()
    logging.info(f"Computing the diff scores using the retrieval API for diff ranking...")

    res = rank_all_diffs(reverse_diffs, retrieval_api_uri)

    logging.info(f"Diff scoring took {time.time() - start} seconds...")

    logging.info(yaml.dump(res, indent=4))

    with open(args.output_path, 'w') as yml:
        yaml.dump(res, yml, allow_unicode=True)

    logging.info('Finished running diff-ranker!')