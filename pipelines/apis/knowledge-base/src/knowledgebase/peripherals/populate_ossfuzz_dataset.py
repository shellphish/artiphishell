import git
import os
import json
import logging

from unidiff import PatchSet, PatchedFile
import difflib

import traceback

import json
from tqdm import tqdm
import pandas as pd

from tqdm.auto import tqdm
from pathlib import Path

from ..models.vulnerability_patches import VulnerabilityPatch, Project
from ..models import git_repo
from ..settings import *
from ..models.git_repo import FileModification, FunctionModification, SourceFile
from ..models.syzkaller import CrashReport
from ..clients.embedding_api_client import EmbeddingsAPI
from ..clients.neo4j_client import Neo4JServer

from ..clang_utils import get_functions_in_commit_file
from ..clients.parser_api_client import ParserAPI
from ..settings import LINUX_KERNEL_FILE_SUFFICES


def patch_file_filter_condition(f: PatchedFile):
    if 'test' not in f.path and f.path.split('.')[-1] in LINUX_KERNEL_FILE_SUFFICES:
        return True
    else:
        return False

# class to populate the knowledge base with embeddings and patch-related nodes/relationships
class Populater:
    def __init__(self, neo4j:Neo4JServer, repo:git.Repo, embs_api:EmbeddingsAPI):
        self.repo = repo

        self.neo4j = neo4j
        self.embs_api = embs_api

    def generate_patch_report_from_diff(self, patch_set, vuln_sha, fix_sha):

        report = {}
        patched_files =  [f.path for f in patch_set.modified_files if patch_file_filter_condition(f)]

        report['patched_files'] = patched_files
        report['file_diffs'] = [str(f) for f in patch_set.modified_files if patch_file_filter_condition(f)]

        report['patched_funcs'] = [[] for f in patched_files]
        report['before_funcs'] = [[] for f in patched_files]
        report['after_funcs'] = [[] for f in patched_files]
        report['func_diffs'] = [[] for f in patched_files]

        for ii, fpath in enumerate(patched_files):
            before = get_functions_in_commit_file(self.repo, vuln_sha, fpath)
            after = get_functions_in_commit_file(self.repo, fix_sha, fpath)
            patched_funcs = ParserAPI.find_patched_funcs(before, after)
            for func in patched_funcs:
                report['patched_funcs'][ii].append(func)
                report['before_funcs'][ii].append(before[func])
                report['after_funcs'][ii].append(after[func])
                func_diff = difflib.unified_diff(before[func]['src'].split('\n'), after[func]['src'].split('\n'), fromfile='before_func', tofile='after_func')
                func_diff = '\n'.join(list(iter(func_diff)))
                report['func_diffs'][ii].append(func_diff)

        return report

        
    def _generate_generic_patched_file_and_func_nodes(self, report, patch_node, patch_commit_node, project_node):

        for file_id, fpath in enumerate(report['patched_files']):

            sf_node = SourceFile.get_or_create({'path': fpath})[0]

            project_node.sourceFiles.connect(sf_node)

            sf_node.touched_by_commit.connect(patch_commit_node)

            diff_text = report['file_diffs'][file_id]
            
            code_type = 'file_diff'

            diff_emb = self.embs_api.get_code_embeddings(diff_text, code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)

            code_type = 'file'

            
            file_mod_node = FileModification.create(
                {
                    'diffEmbeddings': diff_emb,
                    'diffText': diff_text
                }
            )[0].save()


            file_mod_node.modified_file.connect(sf_node)

            patch_node.file_modifications.connect(file_mod_node)

            for func_id, _ in enumerate(report['patched_funcs'][file_id]):
                
                code_type = 'function'

                before_func = report['before_funcs'][file_id][func_id]
                after_func = report['after_funcs'][file_id][func_id]
                func_diff = report['func_diffs'][file_id][func_id]

                before_emb = self.embs_api.get_code_embeddings(before_func['src'], \
                                                                code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)
                
                after_emb = self.embs_api.get_code_embeddings(after_func['src'], \
                                                              code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)

                function_node = FunctionModification.create(
                    {
                        'identifier': before_func['identifier'],
                        'fullName': before_func['full_name'],
                        'accessModifier': before_func['access'],
                        'signature': before_func['signature'],
                        'returnType': before_func['return'],
                        'beforePatchEmbeddings': before_emb,
                        'beforePatchSourceCode': before_func['src'],
                        'afterPatchEmbeddings': after_emb,
                        'afterPatchSourceCode': after_func['src'],
                        'patchDiff': func_diff
                    }
                )[0].save()

                function_node.contained_in.connect(file_mod_node) 

        
    def _create_patch_node(self, vuln_sha, patch_sha, patch_identifier):

        patch_node = VulnerabilityPatch.create(
            { 
                'vulnerabilityIdentifier': patch_identifier
            }
        )[0].save()

        vuln_commit_node = git_repo.Commit.from_git_commit(self.repo.commit(vuln_sha), limited=True)
        vuln_commit_node.save()

        patch_node.vulnerable_commit.connect(vuln_commit_node)

        patch_commit_node = git_repo.Commit.from_git_commit(self.repo.commit(patch_sha), limited=True)
        patch_commit_node.save()

        patch_node.patching_commit.connect(patch_commit_node)


        return patch_node, patch_commit_node
    

    def create_project_node(self, project_name, project_source='oss-fuzz'):
        
        project_node = Project.get_or_create(
            {
                'projectName': project_name,
                'projectSource': project_source
            }
        )[0]

        return project_node
    

    def create_crash_node(self, crash_content, crash_type, sanitizer, severity):

        crash_node = CrashReport.create(
            { 
                'sanitizer': sanitizer,
                'report_type': crash_type,
                'report_content': crash_content,
                'severity': severity,
                'report_embeddings': self.embs_api.get_code_embeddings(crash_content, from_model='codet5p-110m-embedding')
            }
        )[0].save()

        return crash_node


def check_patch_already_populated(neo4j_server:Neo4JServer, identifier):

    query = (
        f"MATCH (n:VulnerabilityPatch) WHERE n.vulnerabilityIdentifier = '{identifier}' RETURN COUNT(n) as cnt"
    )

    res = neo4j_server.execute_query(query)

    if res is None or res['cnt'][0] == 0:
        return False
    else:
        return True


def process_oss_fuzz_entry(download_path, vulns_path, report_path, crashes_path, neo4j_server, embs_api):

    full_path = os.path.join(vulns_path, report_path)

    logging.warning(full_path)

    with open(full_path, 'r') as fp:
        cur_report = json.load(fp)

    # must exist
    project = cur_report['project']
    repo_addr = cur_report['repo_addr']

    ossfuzz_id = cur_report.get('localId', report_path.split('.')[0])

    patch_node_id = f'ossfuzz-{project}-{ossfuzz_id}'

    if check_patch_already_populated(neo4j_server, patch_node_id):
        logging.warning(f'Patch with node id: {patch_node_id} is already populated.')
        return patch_node_id, True

    project_download_path = os.path.join(download_path, project)

    logging.warning(f'Processing OSS-Fuzz Patch ID: {ossfuzz_id} for project: {project}, from path {full_path}.')

    # download the project from github
    if not os.path.isdir(project_download_path):
        repo = git.Repo.clone_from(repo_addr, project_download_path)
    else:
        repo = git.Repo(project_download_path)

    fix_sha = cur_report['fix_commit']

    # TODO - can we handle these cases?
    if not isinstance(fix_sha, str):
        if len(fix_sha) > 1:
            logging.warning(f'Processing OSS-Fuzz Patch ID: {ossfuzz_id} for project: {project}, has multiple fix commits, skipping.')
            return patch_node_id, False
        else:
            fix_sha = fix_sha[0]

    vuln_sha = repo.commit(fix_sha).parents[0].hexsha

    diff = repo.git.diff(vuln_sha, fix_sha)
    patch_set = PatchSet(diff)

    # TODO - focus only on C/C++ files that can be parsed with CLANG-CINDEX
    modified_files =  [(ii, f.path) for ii, f in enumerate(patch_set.modified_files) if patch_file_filter_condition(f)] 

    num_files = len(modified_files)

    if num_files == 0:
        logging.warning(f'OSS-Fuzz Patch ID: {ossfuzz_id} for project: {project} does not have enough files, skipping.')
        return patch_node_id, False
    
    modified_indices, modified_files =  zip(*modified_files)
    
    num_files, num_hunks = len(modified_files), sum([len(patch_set.modified_files[ii]) for ii in modified_indices])

    if num_files > 1 or num_hunks > 1:
        logging.warning(f'OSS-Fuzz Patch ID: {ossfuzz_id} for project: {project} has too many diff hunks, skipping.')
        return patch_node_id, False

    populater = Populater(neo4j_server, repo, embs_api)

    project_node = populater.create_project_node(project, 'oss-fuzz')

    patch_node, patch_commit_node = populater._create_patch_node(vuln_sha, fix_sha, patch_node_id)

    with open(os.path.join(crashes_path, f'{ossfuzz_id}_vul.log'), 'r') as fp:
        crash_content = fp.read()

    sanitizer = cur_report.get('sanitizer', 'UNKNOWN')
    crash_type = cur_report.get('crash_type', 'UNKNOWN')
    severity = cur_report.get('severity', 'UNKNOWN')

    crash_node = populater.create_crash_node(crash_content, crash_type, sanitizer, severity)

    crash_node.patch_node.connect(patch_node)

    project_node.vulnerabilities.connect(patch_node)

    report = populater.generate_patch_report_from_diff(patch_set, vuln_sha, fix_sha)

    populater._generate_generic_patched_file_and_func_nodes(report, patch_node, patch_commit_node, project_node)

    return patch_node_id, True

def main():

    import argparse

    parser = argparse.ArgumentParser(description='Prepare the syzbot crashes dataset')

    parser.add_argument('neo4j_bolt_url', help='Bolt URL for the Neo4J server')
    parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
    parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
    parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')

    parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')
    parser.add_argument('--syzbot_dataset', default='./download/syzbot_repros_processed.json', 
                        help='The processed syzbot dataset (Created by prepare_syzbot_repros_dataset.py)')
    
    parser.add_argument('--download_path', help='Path to clone oss-fuzz projects', default='./download/oss_fuzz_targets')
    parser.add_argument('--ossfuzz_dataset', help='Path to the oss-fuzz dataset (cloned from https://github.com/shellphish-support-syndicate/OSV-ARVO)', default='./download/OSV-ARVO')
    args = parser.parse_args()


    neo4j_server = Neo4JServer(
        args.neo4j_bolt_url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    Path(args.download_path).mkdir(parents=True, exist_ok=True)

    embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)

    vulns_path = os.path.join(args.ossfuzz_dataset, 'vulns')
    crashes_path = os.path.join(args.ossfuzz_dataset, 'crashes')

    all_reports = os.listdir(vulns_path)

    logging.warning(f'{len(all_reports)} vulnerability reports were found under: {vulns_path}')
    
    all_populated_patches = []

    for ii, report_path in tqdm(enumerate(all_reports), total=len(all_reports)):

        try:
            patch_node_id, is_populated = process_oss_fuzz_entry(args.download_path, vulns_path, report_path, crashes_path, neo4j_server, embs_api)
            if is_populated:
                all_populated_patches.append((ii, patch_node_id))

        except:
            logging.error(f'Could not process {report_path}')
            logging.error(traceback.format_exc())
            continue
    
    logging.warning(f'The last populated patch: {all_populated_patches[-1]}, total number of populated patches: {len(all_populated_patches)}')

    # create the indexes for retrieval
    emb_size = embs_api.av_models['codet5p-110m-embedding']
    neo4j_server.create_vector_index('retrieve_vuln_function', 'FunctionModification', 'beforePatchEmbeddings', emb_size)


# TODO - using the syzcoverage knowledge base for now.
# kb_populate_ossfuzz_dataset bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7689 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152