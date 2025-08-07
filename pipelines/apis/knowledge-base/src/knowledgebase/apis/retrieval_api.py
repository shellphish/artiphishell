import logging
import os
import pandas as pd
import difflib
import time
import numpy as np

from flask import Flask, request, jsonify

from ..settings import *
from ..shared_utils import is_authorized

from ..clients.neo4j_client import Neo4JServer
from ..clients.embedding_api_client import EmbeddingsAPI
from typing import Dict
from traceback import format_exc

app = Flask(__name__)

class Retriever:
    def __init__(self, neo4j_servers: Dict[str, Neo4JServer], embs_api:EmbeddingsAPI):

        self.neo4j_servers = neo4j_servers
        self.embs_api = embs_api

        time.sleep(20) # sleep for 20 seconds to give knowledge bases time to start

        self.test_access_and_crash()


    # test access to all neo4j_servers and embs api, crash if not available
    def test_access_and_crash(self):
        
        for kb_name, server in self.neo4j_servers.items():
            ret = server.execute_query('MATCH (n) RETURN COUNT(n) as cnt')

            if ret is not None:
                logging.warning(f'RetrievalAPI::Knowledge base: {kb_name} - contains {ret["cnt"]} nodes')
            else:
                logging.critical(f'RetrievalAPI::Knowledge base: {kb_name} with URI {kb_urls.index(kb_name)} cannot be accessed, crashing...')
                exit(1)

        embs = embs_api.get_code_embeddings('int foo = 5', code_type='function', from_model=DEFAULT_EMBEDDING_MODEL)

        try:
            logging.warning(f'RetrievalAPI::EmbeddingAPI returns {embs.shape} dimensional vector')
        except:
                logging.critical(f'RetrievalAPI::EmbeddingsAPI cannot be reached at {args.embeddings_api_url}, crashing...')
                logging.critical
                exit(1)
        

    def select_knowledge_base(self, kb_name):

        if kb_name not in self.neo4j_servers:
            logging.warning(f'{kb_name} is not in available Neo4J servers, defaulting to Jenkins KB')
            neo4j = self.neo4j_servers['Jenkins']
        else:
            neo4j = self.neo4j_servers[kb_name]

        return neo4j

    def retrieve_patched_funcs_w_code(self, query_func:str, neo4j:Neo4JServer, index_name='retrieve_vuln_function', node_type='FunctionModification', num_return=10):

        query_embs = self.embs_api.get_code_embeddings(query_func, code_type='function', from_model=DEFAULT_EMBEDDING_MODEL)

        query = (
            f"CALL db.index.vector.queryNodes('{index_name}', {num_return}, toFloatList({query_embs.tolist()}))"
            "YIELD node AS n, score "
            f"MATCH (n:{node_type}) "
            "RETURN ID(n), n.fullName, n.signature, n.returnType, n.accessModifier, n.beforePatchSourceCode, n.afterPatchSourceCode, n.patchDiff, score"
        )
        # logging.info(f'Executed query: {query}')

        df = neo4j.execute_query(query, return_type='pd')

        return df

    def retrieve_patched_funcs_w_name(self, func_name:str, neo4j: Neo4JServer, index_name='retrieve_vuln_function',
                                 node_type='FunctionModification', index_property='beforePatchEmbeddings', num_return=10):


        query = (
            f"MATCH (n:{node_type}) "
            f"WHERE n.functionName = {func_name} "
            f"CALL db.index.vector.queryNodes('{index_name}', {num_return}, toFloatList({index_property.tolist()}))"
            "YIELD node AS n, score "
            f"MATCH (n:{node_type}) "
            "RETURN ID(n), n.fullName, n.signature, n.returnType, n.accessModifier, n.beforePatchSourceCode, n.afterPatchSourceCode, n.patchDiff, score"
        )

        df = neo4j.execute_query(query, return_type='pd')

        return df
    
    
    def _get_vulnerability_description_kernel(self, neo4j:Neo4JServer, func_node_id):

        query = (
            'MATCH (c:SyzCrash)-->(p:VulnerabilityPatch)-->(f:FileModification)-->(t:FunctionModification) '
            f'WHERE ID(t) = {func_node_id} '
            'RETURN c.crash_title, c.parsed_report, p.vulnerability_description_embeddings'
        )

        df: pd.DataFrame = neo4j.execute_query(query, return_type='pd')
        crash_title = df['c.crash_title'].to_numpy()[0]
        crash_report = df['c.parsed_report'].to_numpy()[0]
    

        if crash_report is not None:
            vuln_description = crash_title + ' ' + crash_report.split('\n')[0]
        elif crash_title is not None:
            vuln_description = crash_title
        else:
            vuln_description = 'VULNERABILITY DESCRIPTION CANNOT BE FOUND.'

        vuln_embeddings = df['p.vulnerability_description_embeddings'].to_numpy()[0]

        if vuln_embeddings is None:
            logging.warning('Vulnerability description embeddings not found.')
            #vuln_embeddings = self.embs_api.get_code_embeddings(vuln_description_for_embs, from_model=DEFAULT_EMBEDDING_MODEL).tolist()
            embeddings = np.random.randn(1536)
            embeddings = embeddings / np.linalg.norm(embeddings).tolist()
        
        return (vuln_description, vuln_embeddings)

    def _get_vulnerability_description_generic_c(self, neo4j:Neo4JServer, func_node_id):

        query = (
            'MATCH (c:CrashReport)-->(p:VulnerabilityPatch)-->(f:FileModification)-->(t:FunctionModification) '
            f'WHERE ID(t) = {func_node_id} '
            'RETURN c.report_type, p.vulnerability_description_embeddings'
        )

        df: pd.DataFrame = neo4j.execute_query(query, return_type='pd')
        vuln_description = df['c.report_type'].to_numpy()[0]

        if vuln_description is None:
            vuln_description = 'VULNERABILITY DESCRIPTION CANNOT BE FOUND.'

        vuln_embeddings = df['p.vulnerability_description_embeddings'].to_numpy()[0]

        if vuln_embeddings is None:
            logging.warning('Vulnerability description embeddings not found.')
            #vuln_embeddings = self.embs_api.get_code_embeddings(vuln_description_for_embs, from_model=DEFAULT_EMBEDDING_MODEL).tolist()
            embeddings = np.random.randn(1536)
            embeddings = embeddings / np.linalg.norm(embeddings).tolist()

        return (vuln_description, vuln_embeddings)


    def _get_vulnerability_description_jenkins(self, neo4j:Neo4JServer, func_node_id):

        query = (
            'MATCH (c:JenkinsAdvisory)-->(p:VulnerabilityPatch)-->(f:FileModification)-->(t:FunctionModification) '
            f'WHERE ID(t) = {func_node_id} '
            'RETURN c.vulnerability_description, p.vulnerability_description_embeddings'
        )

        df: pd.DataFrame = neo4j.execute_query(query, return_type='pd')

        vuln_description = df['c.vulnerability_description'].to_numpy()[0]

        if vuln_description is None:
            vuln_description = 'VULNERABILITY DESCRIPTION CANNOT BE FOUND.'

        
        vuln_description_for_embs =  vuln_description.split('\n')[0] # the first line is the summary of the vulnerability
  
        vuln_embeddings = df['p.vulnerability_description_embeddings'].to_numpy()[0]

        if vuln_embeddings is None:
            logging.warning('Vulnerability description embeddings not found.')
            #vuln_embeddings = self.embs_api.get_code_embeddings(vuln_description_for_embs, from_model=DEFAULT_EMBEDDING_MODEL).tolist()
            embeddings = np.random.randn(1536)
            embeddings = embeddings / np.linalg.norm(embeddings).tolist()

        return (vuln_description, vuln_embeddings)


    def get_vulnerability_description(self, neo4j:Neo4JServer, func_node_ids, kb_name='Kernel'):

        details = []

        for func_node_id in func_node_ids:
            
            if kb_name == 'Kernel':
                details.append(self._get_vulnerability_description_kernel(neo4j, func_node_id))
            
            elif kb_name == 'Generic_C':
                details.append(self._get_vulnerability_description_generic_c(neo4j, func_node_id))

            elif kb_name == 'Jenkins':
                details.append(self._get_vulnerability_description_jenkins(neo4j, func_node_id))

            else:
                vuln_description = f'VULNERABILITY DESCRIPTION RETRIEVAL NOT IMPLEMENTED FOR {kb_name} KB.'
                # still return some embeddings in case the downstream component is not handling the errors
                vuln_embeddings = self.embs_api.get_code_embeddings(vuln_description, from_model=DEFAULT_EMBEDDING_MODEL).tolist()
                details.append((vuln_description, vuln_embeddings))

        return details
    
    def retrieve_func_metadata(self, function_content_node_id, neo4j: Neo4JServer):

        query = (
            f'MATCH (m)-[x]->(n:FileContent)-->(j:FunctionContent) WHERE ID(j) = {function_content_node_id} and (m:TargetRepository or m:SourceRepository) '
            f'RETURN CASE TYPE(x) WHEN "FILE_AT_TARGET" THEN m.targetPath ELSE m.fromCommit END AS ret, TYPE(x)'
        )

        df = neo4j.execute_query(query, return_type='pd')

        from_repo = df['TYPE(x)'][0].split('_')[-1]

        repo_identifier = df['ret'][0]

        query = f'MATCH (n:SourceFile)--(k:FileContent)--(p:FunctionContent) WHERE ID(p) = {function_content_node_id} RETURN n.path'

        df = neo4j.execute_query(query, return_type='pd')

        file_path = df['n.path'][0]


        return {
            'path': file_path,
            'from_repo': from_repo,
            'repo_identifier': repo_identifier
        }
    

    def retrieve_patched_func_node_metadata(self, function_node_id, neo4j:Neo4JServer, is_generic=False):
        query = f'MATCH (n:VulnerabilityPatch)--(k:FileModification)--(p:FunctionModification) WHERE ID(p) = {function_node_id} RETURN ID(n), ID(k)'

        df = neo4j.execute_query(query, return_type='pd')

        vul_node_id = df['ID(n)'][0]
        filemod_id = df['ID(k)'][0]

        query = f'MATCH (n:VulnerabilityPatch)-[x]-(k:Commit) WHERE ID(n) = {vul_node_id} RETURN TYPE(x), k.sha, k.message'
        df = neo4j.execute_query(query, return_type='pd')

        assert len(df) == 2, 'VulnerabilityPatch node is connected to too many Commit nodes'

        for ii in range(2):
            if df['TYPE(x)'][ii] == 'PATCHING_COMMIT':
                patch_sha = df['k.sha'][ii]
                patch_message = df['k.message'][ii]

            if df['TYPE(x)'][ii] == 'VULNERABLE_COMMIT':
                vuln_sha = df['k.sha'][ii]


        query = f'MATCH (n:FileModification)--(k:SourceFile) WHERE ID(n) = {filemod_id} RETURN k.path'
        df = neo4j.execute_query(query, return_type='pd')

        assert len(df) == 1, 'FileModification node is connected to too many SourceFile nodes'

        file_path = df['k.path'][0]

        info = {
            'path': file_path,
            'commit_vulnerable': vuln_sha,
            'commit_patched': patch_sha,
            'patch_message': patch_message
        }


        # get the project name for the generic knowledge bases
        if is_generic:
            query = f'MATCH (n:Project)-->(m:VulnerabilityPatch)-->(k:FileModification)-->(t:FunctionModification) WHERE ID(t) = {function_node_id} RETURN n.projectName'
            df = neo4j.execute_query(query, return_type='pd')

            project_name = df['n.projectName'][0]

            info['project_name'] = project_name

        return info
    
    def get_most_similar_function_patches_only_scores(self, vector_search_results:pd.DataFrame):
        scores = vector_search_results['score'].to_numpy()
        node_ids = vector_search_results['ID(n)'].to_numpy()
        patch_diffs = vector_search_results['n.patchDiff'].to_numpy()
        full_names = vector_search_results['n.fullName'].to_numpy()

        results = []

        ranking  = 1

        for ii in range(len(node_ids)):

            cur_res = {'score': scores[ii], 'ranking': ranking, 'code_diff': patch_diffs[ii], 'full_name': full_names[ii]}
            
            results.append(cur_res)

            ranking += 1

        return results


    def get_most_similar_function_patches(self, vector_search_results:pd.DataFrame, neo4j:Neo4JServer, is_patch=True, is_generic=False):

        # from patch retrieval
        # "RETURN ID(n), n.fullName, n.signature, n.returnType, n.accessModifier, n.beforePatchSourceCode, n.afterPatchSourceCode, n.patchDiff, score"

        # from func retrieval
        # "RETURN ID(n), n.fullName, n.identifier, n.signature, n.returnType, n.accessModifier, n.sourceCode, score"

        node_ids = vector_search_results['ID(n)'].to_numpy()
        full_names = vector_search_results['n.fullName'].to_numpy()
        signatures = vector_search_results['n.signature'].to_numpy()
        return_types = vector_search_results['n.returnType'].to_numpy()
        access = vector_search_results['n.accessModifier'].to_numpy()

        if is_patch:
            before_texts = vector_search_results['n.beforePatchSourceCode'].to_numpy()
            after_texts = vector_search_results['n.afterPatchSourceCode'].to_numpy()
            patch_diffs = vector_search_results['n.patchDiff'].to_numpy()
        else:
            sources = vector_search_results['n.sourceCode'].to_numpy()

        scores = vector_search_results['score'].to_numpy()

        ranking = 1
        results = []
        for ii in range(len(node_ids)):

            node_id = node_ids[ii]

            if is_patch:
                cur_res = self.retrieve_patched_func_node_metadata(node_id, neo4j, is_generic)
            else:
                cur_res = self.retrieve_func_metadata(node_id, neo4j)

            cur_res.update({
                'signature': signatures[ii],
                'return_type': return_types[ii],
                'access': access[ii],
                'full_name': full_names[ii],
                'ranking': ranking,
                'score': scores[ii],
            })

            if is_patch:

                patch_diff = patch_diffs[ii]
                
                if patch_diff is None:
                    patch_diff = difflib.unified_diff(before_texts[ii].split('\n'), after_texts[ii].split('\n'), fromfile='before_func', tofile='after_func')
                    patch_diff = '\n'.join(list(iter(patch_diff)))

                cur_res.update({
                    'code_vulnerable': before_texts[ii],
                    'code_patched': after_texts[ii],
                    'code_diff': patch_diff
                })
            else:
                cur_res.update({
                    'source': sources[ii]
                })

            ranking += 1
            results.append(cur_res)

        return results, node_ids
    
@app.route('/')
def api_spec():
    return jsonify({
        'endpoints': {
            '/api/funcs/closest_vuln': {
                'methods': ['POST'],
                'description': 'Given the query (e.g., function code), find the closest vulnerable functions and retrieve their patched versions.',

                'example': {
                    'query': 'Hello!',
                    'num_return': 2,
                    'auth_key': 'ENTER_YOUR_AUTH_KEY',
                    'knowledge_base': 'Jenkins'
                },
                'response': {
                    'status':
                    'success',
                    'result': [
                        {
                            "path": "bla.java",
                            "code_vulnerable": "Hello",
                            "code_patched": "Hello World!",
                            "code_diff": "+ World!",
                            "score": 0.9 #  #the similarity score between the query and code_vulnerable
                        }, {
                            "path":"foo.java"
                        }
                    ]
                }
            },

            '/api/funcs/closest_diff': {
                'methods': ['POST'],
                'description': 'Given the query (e.g., diff), find the closest diff for a FunctionModification (i.e. a code patch to a function).',

                'example': {
                    'query': '<DIFF>!',
                    'num_return': 2,
                    'auth_key': 'ENTER_YOUR_AUTH_KEY',
                    'knowledge_base': 'Jenkins'
                },
                'response': {
                    'status':
                    'success',
                    'result': [
                        {
                            "path": "bla.java",
                            "code_vulnerable": "Hello",
                            "code_patched": "Hello World!",
                            "code_diff": "+ World!",
                            "score": 0.9 #the similarity score between the query and code_diff
                        }, {
                            "path":"foo.java"
                        }
                    ]
                }
            },
            '/api/funcs/closest_diff': {
                'methods': ['POST'],
                'description': 'Given the query (e.g., diff), find the closest diff for a FunctionModification (i.e. a code patch to a function).',

                'example': {
                    'query': '<DIFF>!',
                    'num_return': 2,
                    'auth_key': 'ENTER_YOUR_AUTH_KEY',
                    'knowledge_base': 'Jenkins'
                },
                'response': {
                    'status':
                    'success',
                    'result': [
                        {
                            "path": "bla.java",
                            "code_vulnerable": "Hello",
                            "code_patched": "Hello World!",
                            "code_diff": "+ World!",
                            "score": 0.9 #the similarity score between the query and code_diff
                        }, {
                            "path":"foo.java"
                        }
                    ]
                }
            },
            '/api/info/available_kbs': {
                'methods': ['POST'],
                'description': 'List available knowledge bases',
                'example': {
                    'auth_key': 'ENTER_YOUR_AUTH_KEY'
                },
                'response': [
                    'Jenkins', 
                    'Kernel', 
                    'Generic_C'
                    ]
            }

        }
    })



@app.route('/api/info/available_kbs', methods=['POST'])
def get_available_knowledge_bases():
    try:
        data = request.get_json(force=True)

        if not is_authorized(data):
            return jsonify(AUTH_FAIL_RESPONSE), 401

        return jsonify(list(neo4j_servers.keys()))
    
    except Exception as e:
        return jsonify({'error': format_exc()}), 500



def retrieve_func_modification(search_index, data, score_only=False):
    try:
        if not is_authorized(data):
            return None, 401

        query = data['query']
        num_return = data.get('num_return', 5)
        node_type = 'function_patch'
        knowledge_base = data.get('knowledge_base', 'Jenkins')
        neo4j = retriever.select_knowledge_base(knowledge_base)

        search_results = retriever.retrieve_patched_funcs_w_code(query, neo4j, search_index, INDEXES[node_type]['node_name'], num_return)

        if not score_only:
            results, func_node_ids = retriever.get_most_similar_function_patches(search_results, neo4j, is_patch=True, is_generic= 'Generic' in knowledge_base)

            # TODO - implement this for the rest of the knowledge bases

            vuln_details = retriever.get_vulnerability_description(neo4j, func_node_ids, knowledge_base)
            for ii in range(len(results)):
                results[ii].update({'vulnerability_description': vuln_details[ii][0], 'vulnerability_description_embedding': vuln_details[ii][1]})
                    
            logging.info(f'{search_index}:: Retrieved {len(results)} functions')

        else:
            results = retriever.get_most_similar_function_patches_only_scores(search_results)

        response = {
            'status': 'success',
            'result': results
        }
        return response, 200

    except Exception as e:
        exc_str = format_exc()
        return exc_str, 500


@app.route('/api/funcs/closest_vuln', methods=['POST'])
def retrieve_patched_func_from_vuln():
    data = request.get_json(force=True)

    result, status = retrieve_func_modification('retrieve_vuln_function', data, score_only=False)

    if status == 401:
        return jsonify(AUTH_FAIL_RESPONSE), 401
    
    elif status == 200:
        return jsonify(result), 200
    
    else:
        return jsonify({'error': result}), status


@app.route('/api/funcs/closest_diff', methods=['POST'])
def retrieve_closest_diffs():
    data = request.get_json(force=True)

    result, status = retrieve_func_modification('retrieve_similar_diff', data, score_only=True)

    if status == 401:
        return jsonify(AUTH_FAIL_RESPONSE), 401
    
    elif status == 200:
        return jsonify(result), 200
    
    else:
        return jsonify({'error': result}), status


import argparse

# these probably should be read from a config file
parser = argparse.ArgumentParser(description='Create vector index and do some basic retrieval on Neo4J')

parser.add_argument('neo4j_bolt_url_jenkins', help='Bolt URL for the Neo4J server (Jenkins)')
parser.add_argument('neo4j_bolt_url_kernel', help='Bolt URL for the Neo4J server (Kernel)')
parser.add_argument('neo4j_bolt_url_generic_c', help='Bolt URL for the Neo4J server (Generic_C)')

parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')
parser.add_argument('--retrieval-host', help='Host name for the retrieval API', default='localhost')
parser.add_argument('--retrieval-port', help='Port for the retrieval API', default=48751)
parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO)
logging.info('Retrieval API Server Started.')

p = os.path.dirname(os.path.realpath(__file__))
# read the API configuration -- hosts, ports etc.


kb_names = ['Jenkins', 'Kernel', 'Generic_C']
kb_urls = [args.neo4j_bolt_url_jenkins, args.neo4j_bolt_url_kernel, args.neo4j_bolt_url_generic_c]

neo4j_servers = {}

for kb_name, url in zip(kb_names, kb_urls):

    neo4j_server = Neo4JServer(
        url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    neo4j_servers[kb_name] = neo4j_server

embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)

retriever = Retriever(neo4j_servers, embs_api)

def main():
    app.run(
        host=args.retrieval_host,
        port=args.retrieval_port,
        debug=False
    )
