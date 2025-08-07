import git
import os
import json
import csv
import sys
import logging

from unidiff import PatchSet, PatchedFile
import difflib

import traceback

import json
from tqdm import tqdm
import pandas as pd

from tqdm.auto import tqdm
from pathlib import Path

from ..models.vulnerability_patches import VulnerabilityPatch
from ..models import git_repo
from ..settings import *
from ..models.git_repo import FileModification, FunctionModification, SourceFile
from ..models.syzkaller import SyzCrash, SyzReproC, SyzProg, CrashConfig
from ..clients.embedding_api_client import EmbeddingsAPI
from ..clients.neo4j_client import Neo4JServer

from ..clang_utils import get_functions_in_commit_file
from ..clients.parser_api_client import ParserAPI
from ..settings import LINUX_KERNEL_FILE_SUFFICES
from ..peripherals.kasan_parser_lite import kasan_report_parser

from neomodel import DoesNotExist 
from ..models.cve import CWE
from ..shared_utils import to_epoch_ts


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


    def add_cwe_id_to_node(self, crash_node, cwe_name):
        # connect with CWE node if that info exists
        try: 
            cwe_node = self.get_cwe_node_from_name(cwe_name)
            # logging.info(cwe_node.description)
            crash_node.cwe_info.connect(cwe_node)
        except (DoesNotExist, RuntimeError) as e:
            # logging.warning(f'The CWE with description: {cwe_name} does not exist in KB')
            return


    def get_cwe_node_from_name(self, name):

        # logging.info(name)

        if len(name) < 2:
            raise RuntimeError

        cwe_node = CWE.nodes.get(name=name)

        return cwe_node


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


    
    def create_config_node(self, config, commit, time, crash_node):
        
        identifier = CrashConfig.get_identifier(config, commit, time)

        config_node = CrashConfig.create(
            {   
                'identifier': identifier,
                'config': config,
                'crash_commit': commit,
                'crash_time': time
            })[0]
        

        # logging.warning('Config NODE:')
        # logging.warning(config_node.element_id_property)
        
        config_node.config_of.connect(crash_node)

    def create_c_repro_node(self, c_repro, crash_node):

        repro_node = SyzReproC.get_or_create(
            {
                'source': c_repro
            })[0]
        
        crash_node.c_repro.connect(repro_node)

    
    def create_syzprog_node(self, source, crash_node):

        syzprog_identifier = SyzProg.get_identifier(source)

        repro_node = SyzProg.get_or_create(
            {
                'identifier': syzprog_identifier,
                'source': source
            })[0]
        
        crash_node.syz_repro.connect(repro_node)

        
    def _generate_generic_patched_file_and_func_nodes(self, report, patch_node, patch_commit_node):

        for file_id, fpath in enumerate(report['patched_files']):

            sf_node = SourceFile.get_or_create({'path': fpath})[0]

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

    def check_patch_already_populated(self, identifier):

        query = (
            f'MATCH (n:VulnerabilityPatch) WHERE n.vulnerabilityIdentifier = "{identifier}" RETURN COUNT(n) as cnt'
        )

        res = self.neo4j.execute_query(query)

        if res is None or res['cnt'][0] == 0:
            return False
        else:
            return True
        
    def create_patch_node(self, vuln_sha, patch_sha, patch_identifier):


        if self.check_patch_already_populated(patch_identifier):
            logging.warning(rf'Vulnerability with identifier: {patch_identifier} has already been populated...')
            return 

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
    

    def create_crash_node(self, crash_title, crash_report, parsed_report, patch_node=None):

        crash_node = SyzCrash.get_or_create(
            { 
                'crash_title': crash_title,
                'crash_report': crash_report,
                'parsed_report': parsed_report
            }
        )[0].save()


        if patch_node is not None:
            crash_node.patch_node.connect(patch_node)

        return crash_node
    

    def update_c_repro(self, crash_title, new_source):

        crash_node = SyzCrash.get_or_create(
            { 
                'crash_title': crash_title,
            }
        )[0]

        try:
            c_repro_node = crash_node.c_repro[0]
            c_repro_node.source = new_source
            c_repro_node.save()
            return True
        except:
            return False

def main():

    import argparse

    parser = argparse.ArgumentParser(description='Prepare the syzbot crashes dataset')

    parser.add_argument('neo4j_bolt_url', help='Bolt URL for the Neo4J server')
    parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
    parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
    parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')

    parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')
    
    parser.add_argument('--syzbot_dataset', default='./download/corrected_experiment_required_v3.csv', 
                        help='The exported syzbot coverage dataset (Created by su3ry by scraping Syzbot)')


    parser.add_argument('--git_repo', help='Path to the git repo of Linux Kernel to import', default='./download/linux')


    args = parser.parse_args()

    neo4j_server = Neo4JServer(
        args.neo4j_bolt_url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    maxInt = sys.maxsize

    while True:
        # decrease the maxInt value by factor 10 
        # as long as the OverflowError occurs.

        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)


    embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)
    git_repo = git.Repo(args.git_repo)
    populater = Populater(neo4j_server, git_repo, embs_api)
        
    exists = 0
    total = 0

    logger = logging.getLogger()
    # logger.disabled = True

    # dict_keys(['title', 'time', 'crash_commit', 'config', 'c_reproducer', 'crash_report', 'syz_reproducer', 'fix_commit', 'CWE-ID'])
    with open(args.syzbot_dataset, 'r') as fp:
            crepros_dataset = csv.DictReader(fp)
            for ii, e in tqdm(enumerate(crepros_dataset)):

                total += 1
                title = e['title']
                
                # logging.warning(title)

                time = to_epoch_ts(e['time'])
                crash_commit = e['crash_commit']
                fix_commit = e['fix_commit']

                config = e['config']
                c_repro = e['c_reproducer']
                syz_repro = e['syz_reproducer']
                crash_report = e['crash_report']
                cwe_id = e['CWE-ID']

                total += 1

                # if populater.check_patch_already_populated(f'Syzbot::{title}'):
                #     suc = populater.update_c_repro(title, c_repro)
                #     exists += int(suc)

                try:
                    parsed_report = kasan_report_parser(crash_report)
                    if len(parsed_report['pois']) > 0:
                        parsed_report_pois = parsed_report['pois'][0]['poi'].replace('\n', ' ')
                    if len(parsed_report['call_traces']) > 0:
                        parsed_report_call_trace =  '\n'.join([x for x in parsed_report['call_traces'][0] if len(x) > 1])
                    
                    parsed_report = f'{parsed_report_pois}\n{parsed_report_call_trace}'

                except:
                    parsed_report = 'CRASH REPORT PARSER FAILED'

                if len(fix_commit) != 40: # no patch information is available for this crash
                    patch_node = None
                else:
                        
                    exists += 1

                    # parent of the fix commit is the vuln commit
                    vuln_commit = populater.repo.commit(fix_commit).parents[0].hexsha

                    diff = populater.repo.git.diff(vuln_commit, fix_commit)
                    patch_set = PatchSet(diff)

                    patch_node, patch_commit_node = populater.create_patch_node(vuln_commit, fix_commit, f'Syzbot::{title}')

                    report = populater.generate_patch_report_from_diff(patch_set, vuln_commit, fix_commit)

                    populater._generate_generic_patched_file_and_func_nodes(report, patch_node, patch_commit_node)

                crash_node = populater.create_crash_node(title, crash_report, parsed_report, patch_node)

                c_repro_node = populater.create_c_repro_node(c_repro, crash_node)

                syz_repro_node = populater.create_syzprog_node(syz_repro, crash_node)

                config_node = populater.create_config_node(config, crash_commit, time, crash_node)

                populater.add_cwe_id_to_node(crash_node, cwe_id)

    logger.disabled = False

    logging.warning(f'Number of entries in the syzcoverage dataset: {total}, patch exists: {exists}.')

    # create the indexes for retrieval
    # emb_size = embs_api.av_models['codet5p-110m-embedding']
    # populater.neo4j.create_vector_index('retrieve_vuln_function', 'FunctionModification', 'beforePatchEmbeddings', emb_size)


# kb_update_syzbot bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7689 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152