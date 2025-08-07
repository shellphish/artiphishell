import logging
import numpy as np
import pandas as pd
import os
import glob
import time


from tqdm.auto import tqdm
from unidiff import PatchSet
from bs4 import BeautifulSoup
import requests

from ..models.cve import CVE
from ..models.jenkins_security_advisory import JenkinsAdvisory
from ..models.vulnerability_patches import VulnerabilityPatch

import git

from ..settings import *
from ..models.git_repo import FileModification, FunctionModification, FileContent, FunctionContent, TargetRepository, SourceRepository, Commit, SourceFile
from ..shared_utils import CommitFile, TargetFile
from ..clients.embedding_api_client import EmbeddingsAPI
from ..clients.parser_api_client import ParserAPI
from ..clients.neo4j_client import Neo4JServer

# VulnerabilityPatch.vulnerabilityIdentifier (e.g., SECURITY-166)
def scrape_security_advisory_description(url, sec_advisory_id:str):

    # Fetch the webpage content
    response = requests.get(url)

    url_date = 
    webpage_content = response.text

    soup = BeautifulSoup(webpage_content, 'html.parser')

    # Find the <h3> tag with the security id

    ids = [0, 1, 2, 3]

    for id in ids:
        
        if id == 0:
            h3_tag = soup.find('h3', id=sec_advisory_id.upper())
        else:
            h3_tag = soup.find('h3', id=f'{sec_advisory_id.upper()} ({id})')
        
        if h3_tag:
            break
    # Extract the text content
    if h3_tag:
        description = h3_tag.get_text(strip=True)

        current_tag = h3_tag

        for ii in range(20):
            classes = current_tag.get('class', [])

            if classes and classes[0] == 'paragraph' and current_tag.name == 'div':
                break

            current_tag = current_tag.find_next_sibling()

        
        paragraph_contents = []

        desc_tag = current_tag
        classes = desc_tag.get('class', [])

        # Loop through the following siblings until we reach a non-<p> tag
        while classes and classes[0] == 'paragraph' and desc_tag.name == 'div':
            paragraph_contents.append(desc_tag.get_text(strip=True))
            desc_tag = desc_tag.find_next_sibling()
        
        detailed_desc = ' '.join(paragraph_contents)

        full_desc = description + '\n' + detailed_desc

    else:
        full_desc = f'FAILED TO FETCH THE DESCRIPTION FROM URL: {url}'
    
    return full_desc

# class to populate the knowledge base with embeddings and patch-related nodes/relationships
class Populater:
    def __init__(self, neo4j:Neo4JServer, repo:git.Repo, embs_api:EmbeddingsAPI, parser_api:ParserAPI):
        self.repo = repo

        self.neo4j = neo4j
        self.parser_api = parser_api
        self.embs_api = embs_api


    def _create_file_node(self, fpath, file_content):

        code_type = 'file'
        node_type = 'file'

        file_node = FileContent.create(
            {
                'embeddings': self.embs_api.get_code_embeddings(file_content, code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL),
                'sourceCode': file_content,
                'filePath': fpath
            }
        )[0].save()

        return file_node

    def _parse_code_base_generic(self, files_list, rel_path, connect_to_node):
        logging.info(f'{len(files_list)} files will be parsed.')

        for fpath in files_list:
            
            if isinstance(connect_to_node, SourceRepository):

                file_content = CommitFile(self.repo, connect_to_node.fromCommit, fpath, bytes=False).contents

                file_node = self._create_file_node(fpath, file_content)

                file_node.version_at_source.connect(connect_to_node)

            elif isinstance(connect_to_node, TargetRepository):
                
                file_content = TargetFile(fpath).contents
    
                file_node = self._create_file_node(fpath, file_content)

                file_node.version_at_target.connect(connect_to_node)

            else:
                logging.error(f'Parse Code Base: cannot handle node type: {type(connect_to_node)}')
                return
            
            # remove the relative path (target dir) from the source file path for the neo4j nod

            sf_node =  SourceFile.get_or_create({'path': os.path.relpath(fpath, rel_path)})[0]

            file_node.contents_of_file.connect(sf_node)

            functions = self.parser_api.get_functions_from_contents(file_content)

            for id in functions:

                code_type = 'function'
                node_type = 'function'

                embeddings = self.embs_api.get_code_embeddings(functions[id]['src'], code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)

                function_node = FunctionContent.create(
                    {
                        'identifier': id,
                        'fullName': functions[id]['full_name'],
                        'accessModifier': functions[id]['access'],
                        'signature': functions[id]['signature'],
                        'returnType': functions[id]['return_type'],
                        'embeddings': embeddings,
                        'sourceCode': functions[id]['src']
                    }
                )[0].save()

                function_node.contained_in.connect(file_node)
   

    def parse_target_code_base(self, target_dir):

        logging.info(f'Parsing the whole code base to create function nodes for directory: {target_dir}')

        abs_path = os.path.abspath(target_dir)

        # recursively iterate over the target dir
        glob_dir = f'{abs_path}/**/*'

        # filter out the test files and non-java files
        files_list = [f for f in glob.iglob(glob_dir, recursive=True) if os.path.isfile(f) and 'test' not in f and '.java' in f]

        # logging.info(f'{len(files_list)} files will be parsed at {target_dir}')

        connect_to_node = TargetRepository.get_or_create(
            {
                'targetPath': target_dir
            }
        )[0]

        self._parse_code_base_generic(files_list, abs_path, connect_to_node)

    
    def parse_code_base_from_git(self, commit_sha='', distance_to_target_repo=-1, is_closest=False):

        # if commit sha for populating the knowledge base is not provided, use HEAD
        commit_sha = self.repo.head.object.hexsha if commit_sha == '' else commit_sha

        logging.info(f'Parsing the whole code base to create function nodes for commit sha: {commit_sha}')
        
        # get all the files tracked by git in the repo for at a given commit
        tracked_files = self.repo.git.ls_tree('--full-tree', '--name-only', '-r', commit_sha).split('\n')

        # filter out the test files and non-java files
        files_list = [f for f in tracked_files if 'test' not in f and '.java' in f]

        # logging.info(f'{len(files_list)} files will be parsed at {commit_sha} commit')

        repo_name = os.path.basename(self.repo.commit(commit_sha).repo.working_dir)

        connect_to_node = SourceRepository.get_or_create(
                        {
                            'isClosestToTarget': is_closest, # from find_clsest_commit.py
                            'distanceToTarget': distance_to_target_repo, # from find_clsest_commit.py
                            'repo':repo_name,
                            'fromCommit': commit_sha
                        }
                    )[0]
        

        commit_node = Commit.get_or_create(
                        {
                            'repo':repo_name,
                            'sha': commit_sha
                        }
                    )[0]
        
        connect_to_node.commit_rel.connect(commit_node)
        
        self._parse_code_base_generic(files_list, '', connect_to_node)


    def create_test_nodes(self, func_to_test_mapping):
        pass

    # TODO -- get this from neo4j instead of from the repo. CHANGED_FILE_CONTENT edges are incomplete right now.
    def _get_patched_files_between_commits(self, before_sha, after_sha):
        patch_diff = self.repo.git.diff(before_sha, after_sha)
        patch_set = PatchSet(patch_diff)

        # filter out files that were tests or non-java, we only care about chages to files that were related to the patch
        patched_files = [f.path for f in patch_set.modified_files if 'test' not in f.path and '.java' in f.path]
        return patched_files

        # TODO - use this to retrieve the files who is modified by a commit -- CHANGED_FILE_CONTENT edges are missing for now.
        ''''
        query = (
            f"MATCH (n:Commit {{sha: '{commit_sha}'}})-[x:CHANGED_FILE_CONTENT]-(m:SourceFile) "
            "RETURN m"
        )
        return self.neo4j.execute_query(query, return_type='pd')
        '''

    def get_all_cve_referencing_commits(self):
        # return cve_id, vuln_sha, patch_sha, patched_files
        return []


    def get_all_security_advisory_commits(self):
        logging.info('Collecting information on all security advisory patch commits...')

        query = (
            "MATCH (n:JenkinsAdvisory)-[x]->(m:Commit)-[y]-(k:SourceFile) "
            "RETURN n.advisory_id, type(x), m.sha, k.path"
        )

        df: pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')

        sec_adv_patches = []
        for aid, g in df.groupby('n.advisory_id'):
            try:
                vuln_sha = np.unique(g[g['type(x)'] == 'VULNERABLE_COMMIT']['m.sha'].to_numpy())[0]
                patch_sha = np.unique(g[g['type(x)'] == 'OLDEST_PATCH_COMMIT']['m.sha'].to_numpy())[0]
            except:
                continue

            patched_files = self._get_patched_files_between_commits(vuln_sha, patch_sha)
            sec_adv_patches.append((aid, vuln_sha, patch_sha, patched_files))

        logging.info(f'Found: {len(sec_adv_patches)}...')

        logging.debug(sec_adv_patches[0])
        logging.debug(sec_adv_patches[1])

        return sec_adv_patches
    

    def add_vulnerability_descriptions(self):

        query = (
            "MATCH (r:Reference)-->(k:JenkinsAdvisory) " # -->(n:VulnerabilityPatch)-->(t:FileModification)-->(f:FunctionModification) 
            "WHERE r.url CONTAINS 'jenkins.io/security/advisory' "
            "RETURN DISTINCT k.advisory_name, k.advisory_id, r.url"
        )

        df: pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')


        adv_names = df['k.advisory_name'].to_numpy()
        adv_ids = df['k.advisory_id'].to_numpy()
        urls = df['r.url'].to_numpy()

        logging.info(f'Collecting descriptions for {len(adv_names)} Security Advisories')

        for ii, (name, id, url) in enumerate(zip(adv_names, adv_ids, urls)):

            logging.info(f'\nFetching the description from: {url} for {name} ({ii+1}/{len(adv_names)})')

            advisory_node = JenkinsAdvisory.get_or_create(
                { 
                    'advisory_name': name,
                    'advisory_id': id
                }
            )[0]

            url_parsed = url.split('#')[0]

            for trial in range(1, 5):
                try:
                    vuln_description = scrape_security_advisory_description(url_parsed, name)
                    
                    if 'FAILED' in vuln_description:
                        raise RuntimeError
                    else:
                        break

                except:
                    vuln_description = f'FAILED TO FETCH THE DESCRIPTION FROM URL: {url}'

                    time.sleep(trial)
                    continue

            logging.info(vuln_description)

            advisory_node.vulnerability_description = vuln_description
            advisory_node.save()


    def _create_patch_node_generic(self, patch_node: VulnerabilityPatch, vuln_sha, patch_sha, patched_files):
            
            repo_name = os.path.basename(self.repo.commit(patch_sha).repo.working_dir)

            patch_node.vulnerable_commit.connect(
                Commit.get_or_create(
                    {
                        'repo':repo_name,
                        'sha': vuln_sha
                    }
                )[0]
            )

            patch_node.patching_commit.connect(
                Commit.get_or_create(
                    {
                        'repo':repo_name,
                        'sha': patch_sha
                    }
                )[0]
            )
            
            for file_path in patched_files:

                sf_node =  SourceFile.get_or_create({'path': file_path})[0]

                # TODO --- get this from Neo4J
                try:
                    diff_text = self.repo.git.diff(vuln_sha, patch_sha, '--', file_path)
                except Exception as e:
                    logging.error(f'git diff {vuln_sha} - {patch_sha} - {file_path} failed.')
                    continue

                before_content = CommitFile(self.repo, vuln_sha, file_path, bytes=False).contents
                after_content = CommitFile(self.repo, patch_sha, file_path, bytes=False).contents

                diff_text = '\n'.join(diff_text.split('\n')[4:]) # remove the headers from the diff text
                
                code_type = 'file_diff'
                node_type = 'file_diff'

                diff_emb = self.embs_api.get_code_embeddings(diff_text, code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)

                code_type = 'file'
                node_type = 'file_patch'

                before_emb = self.embs_api.get_code_embeddings(before_content, code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)
                after_emb = self.embs_api.get_code_embeddings(after_content, code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)

                file_mod_node = FileModification.create(
                    {
                        'diffEmbeddings': diff_emb,
                        'diffText': diff_text,
                        'beforePatchEmbeddings': before_emb,
                        'beforePatchSourceCode': before_content,
                        'afterPatchEmbeddings': after_emb, 
                        'afterPatchSourceCode': after_content
                    }
                )[0].save()
                
                file_mod_node.modified_file.connect(sf_node)

                patch_node.file_modifications.connect(file_mod_node)

                # source file before the patch
                vuln_funcs = self.parser_api.get_functions_from_contents(before_content)

                # source file after the patch
                patch_funcs = self.parser_api.get_functions_from_contents(after_content)

                # index of the patched function in the b_function_names and b_functions
                patched_func_identifiers = ParserAPI.find_patched_funcs(vuln_funcs, patch_funcs)

                if len(patched_func_identifiers) == 0:
                    logging.info('No function is patched in this file.')
                    continue

                for id in patched_func_identifiers:
                    
                    code_type = 'function'
                    node_type = 'function_patch'

                    before_emb = self.embs_api.get_code_embeddings(vuln_funcs[id]['src'], code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)
                    after_emb = self.embs_api.get_code_embeddings(patch_funcs[id]['src'], code_type=code_type, from_model=DEFAULT_EMBEDDING_MODEL)


                    func_diff = difflib.unified_diff(vuln_funcs[id]['src'], patch_funcs[id]['src'], fromfile='before_func', tofile='after_func')
                    func_diff = '\n'.join(list(iter(func_diff)))

                    function_node = FunctionModification.create(
                        {
                            'identifier': id,
                            'fullName': vuln_funcs[id]['full_name'],
                            'accessModifier': vuln_funcs[id]['access'],
                            'signature': vuln_funcs[id]['signature'],
                            'returnType': vuln_funcs[id]['return_type'],
                            'beforePatchEmbeddings': before_emb,
                            'beforePatchSourceCode': vuln_funcs[id]['src'],
                            'afterPatchEmbeddings': after_emb,
                            'afterPatchSourceCode': patch_funcs[id]['src'],
                            'patchDiff': func_diff
                        }
                    )[0].save()

                    function_node.contained_in.connect(file_mod_node)                
    
    # we only focus on patches referred to in a security advisory
    # this is easy to expand to other patches or commits
                    

    def check_patch_already_populated(self, identifier):

        query = (
            f"MATCH (n:VulnerabilityPatch) WHERE n.vulnerabilityIdentifier = '{identifier}' RETURN COUNT(n) as cnt"
        )

        res = self.neo4j.execute_query(query)

        if res is None or res['cnt'][0] == 0:
            return False
        else:
            return True
    
    def create_patch_nodes_jenkins_advisory(self):
        self.sec_adv_patches = self.get_all_security_advisory_commits()

        for ii, (aid, vuln_sha, patch_sha, patched_files) in enumerate(self.sec_adv_patches):

            vuln_identifier =  f'SECURITY-{aid}'

            if self.check_patch_already_populated(vuln_identifier):
                logging.info(f'Vulnerability with identifier: {vuln_identifier} has already been populated...')
                continue

            patch_node = VulnerabilityPatch.create(
                {   
                    'vulnerabilityIdentifier': vuln_identifier
                }
            )[0].save()

            logging.info(f'Processing Advisory ID: {aid} ({ii+1}/{len(self.sec_adv_patches)})')

            patch_node.sec_advisory.connect(
                JenkinsAdvisory.get_or_create(
                    {
                    'advisory_name': f'SECURITY-{aid}',
                    'advisory_id': aid,
                    }
                )[0]
            )

            self._create_patch_node_generic(patch_node, vuln_sha, patch_sha, patched_files)
    

    def create_patch_nodes_cve(self):
        self.cve_patches = self.get_all_cve_referencing_commits()

        for cve_id, vuln_sha, patch_sha, patched_files in self.cve_patches:

            if self.check_patch_already_populated(cve_id):
                logging.info(f'Vulnerability with identifier: {cve_id} has already been populated...')
                continue


            patch_node = VulnerabilityPatch.create(
                { 
                    'vulnerabilityIdentifier': cve_id
                }
            )[0].save()

            logging.info(f'Processing CVE ID: {cve_id}')

            patch_node.sec_advisory.connect(
                CVE.get_or_create(
                    {
                    'identifier': cve_id
                    }
                )[0]
            )

            self._create_patch_node_generic(patch_node, vuln_sha, patch_sha, patched_files)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info('Started')

    import argparse

    parser = argparse.ArgumentParser(description='Populate the knowledge graph with embeddings and functions')

    parser.add_argument('neo4j_bolt_url', help='Bolt URL for the Neo4J server')
    parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
    parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
    parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')

    parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')

    parser.add_argument('parser_api_url', help='URI for the Parser API')

    parser.add_argument('--git_repo', default='./download/jenkins', help='Path to the git repo to import')
    parser.add_argument('--target_dir', default='./download/jenkins-jenkins-2.366', help='Path to the target directory to import')

    args = parser.parse_args()

    neo4j_server = Neo4JServer(
        args.neo4j_bolt_url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)
    parser_api = ParserAPI(args.parser_api_url)
    repo = git.Repo(args.git_repo)

    # list all unique types of nodes
    # given a node type what it is connected to
    # transaction event lister --- iterate over new nodes added/new edges
    
    try:
        populater = Populater(neo4j_server, repo, embs_api, parser_api)
        
        # create file/function modification nodes for vulnerability patches
        populater.create_patch_nodes_jenkins_advisory()
        populater.create_patch_nodes_cve()

        # create File/Function nodes for a specific git commit, 
        populater.parse_code_base_from_git()
        populater.parse_target_code_base(args.target_dir)

        # # create the indexes for retrieval
        for node_type in INDEXES.keys():
            
            index_node_type = INDEXES[node_type]['node_name']
            emb_size = embs_api.av_models[DEFAULT_EMBEDDING_MODEL]

            for index_name in INDEXES[node_type]['indexes']:
                index_property = INDEXES[node_type]['indexes'][index_name]['property']
                neo4j_server.create_vector_index(index_name, index_node_type, index_property, emb_size)

        logging.info(neo4j_server.get_vector_index_info())

        populater.add_vulnerability_descriptions()


    except:
        logging.error("Exception ",exc_info=1)

# ~/.local/bin/kb_populate_for_retrieval bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7687 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152 http://10.167.213.182:32677 
# kb_populate_for_retrieval bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7687 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152 http://172.17.0.1:32677 --git_repo ./download/jenkins/


# existing functions that have two different source codes -- i.e., modified functions
'''
MATCH (p:FunctionContent)
WITH p.identifier as fid, p.sourceCode as codes
WITH COUNT(DISTINCT codes) as unique_codes, fid
WHERE unique_codes > 1
RETURN fid, unique_codes
'''

# new functions in the target repo located in the files that don't exist for the source/existing repo from git
'''
MATCH (n:TargetCodeBase)-->(m:FileContent)<--(k:SourceFile) 
WITH COLLECT(k.path) as target_paths
MATCH (n:Commit)-->(m:FileContent)<--(k:SourceFile)
WITH COLLECT(k.path) as source_paths, target_paths
WITH REDUCE(s=[] , p in target_paths | CASE WHEN p in source_paths THEN s ELSE s+p END) as new_files
MATCH (n:TargetCodeBase)-->(m:FileContent)<--(k:SourceFile)
WHERE k.path in new_files
MATCH (m)-->(j:FunctionContent)
RETURN k,m,j
'''

# new functions in the target repo located in the files that exist for the source/existing repo
'''
MATCH (n:TargetCodeBase)-->(m:FileContent)<--(k:SourceFile) 
WITH COLLECT(k.path) as target_paths
MATCH (n:Commit)-->(m:FileContent)<--(k:SourceFile)
WITH COLLECT(k.path) as source_paths, target_paths
WITH REDUCE(s=[] , p in target_paths | CASE WHEN p in source_paths THEN s+p ELSE s END) as existing_files
MATCH (n:TargetCodeBase)-->(m:FileContent)<--(k:SourceFile)
WHERE k.path in existing_files
MATCH (m)-->(j:FunctionContent)
WITH COLLECT(j.identifier) as funcs_in_target_in_existing_files, existing_files
MATCH (x:Commit)-->(y:FileContent)<--(z:SourceFile)
WHERE z.path in existing_files
MATCH (y)-->(w:FunctionContent)
WITH COLLECT(w.identifier) as funcs_in_source_in_existing_files, funcs_in_target_in_existing_files
WITH REDUCE(s=[] , p in funcs_in_target_in_existing_files | CASE WHEN p in funcs_in_source_in_existing_files THEN s ELSE s+p END) as new_funcs_in_existing_files
UNWIND new_funcs_in_existing_files as funcs
MATCH (n:TargetCodeBase)-->(m:FileContent)-->(k:FunctionContent)
WHERE k.identifier in funcs
RETURN m,k
'''


# unpopulate queries

'''




'''