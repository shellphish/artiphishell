import logging
import numpy as np
import pandas as pd
import difflib
import openai

from tqdm.auto import tqdm


from ..settings import *
from ..clients.embedding_api_client import EmbeddingsAPI
from ..clients.neo4j_client import Neo4JServer


import argparse

logging.basicConfig(level = logging.INFO)

parser = argparse.ArgumentParser(description='Create vector index and do some basic retrieval on Neo4J')

parser.add_argument('neo4j_bolt_url_jenkins', help='Bolt URL for the Neo4J server (Jenkins)')
parser.add_argument('neo4j_bolt_url_kernel', help='Bolt URL for the Neo4J server (Kernel)')
parser.add_argument('neo4j_bolt_url_generic_c', help='Bolt URL for the Neo4J server (Generic_C)')
parser.add_argument('embeddings_api_url', help='Host name for the embeddings API')

parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')
args = parser.parse_args()


kb_names = ['Jenkins', 'Kernel', 'Generic_C']
kb_urls = [args.neo4j_bolt_url_jenkins, args.neo4j_bolt_url_kernel, args.neo4j_bolt_url_generic_c]
embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)


def get_embeddings(code):
    client = openai.OpenAI(api_key="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")

    response = client.embeddings.create(
        input=code,
        model='-'.join(DEFAULT_EMBEDDING_MODEL.split('-')[1:])
    )

    return response.data[0].embedding

# def get_embeddings(code):
#     return embs_api.get_code_embeddings(code, code_type='function', from_model=DEFAULT_EMBEDDING_MODEL).tolist()


EMB_DIMENSION = len(get_embeddings('x'))

NODE_TAG = 'n'
INDEX_NODE = 'FunctionModification'
INDEX_NAMES = ['retrieve_vuln_function', 'retrieve_patched_function']
INDEX_PROPERTIES = ['beforePatchEmbeddings', 'afterPatchEmbeddings']
SOURCE_PROPERTIES = ['beforePatchSourceCode', 'afterPatchSourceCode']

for kb_name, url in zip(kb_names, kb_urls):

    logging.info(f"Replacing the embeddings for : {kb_name} at {url}")

    neo4j_server = Neo4JServer(
        url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    query = f"MATCH ({NODE_TAG}:{INDEX_NODE}) RETURN ID({NODE_TAG})"
    
    res = neo4j_server.execute_query(query)

    ids = res[f'ID({NODE_TAG})'].to_numpy()

    prop_tags = [f'{NODE_TAG}.{p}' for p in SOURCE_PROPERTIES]
    prop_str = ','.join(prop_tags)

    for node_id in tqdm(ids):
        query = f"MATCH ({NODE_TAG}:{INDEX_NODE}) WHERE ID({NODE_TAG}) = {node_id} RETURN {prop_str}"
        res = neo4j_server.execute_query(query)

        sources = [res[t].to_numpy()[0] for t in prop_tags]

        for prop, code in zip(INDEX_PROPERTIES, sources):
            e = get_embeddings(code)

            query = (
                f'MATCH ({NODE_TAG}:{INDEX_NODE}) WHERE ID({NODE_TAG}) = {node_id} '
                f'SET {NODE_TAG}.{prop} = toFloatList({e}) '
                f'RETURN {NODE_TAG}'
            )

            neo4j_server.execute_query(query)

    for index_name, index_property in zip(INDEX_NAMES, INDEX_PROPERTIES):

        query = f'DROP INDEX `{index_name}`'

        neo4j_server.execute_query(query, 'str')

        # create the index
        query = (
            f"CREATE VECTOR INDEX `{index_name}` "
            f"FOR ({NODE_TAG}:{INDEX_NODE}) ON ({NODE_TAG}.{index_property}) "
            f"OPTIONS {{ indexConfig: {{ `vector.dimensions`: {EMB_DIMENSION}, `vector.similarity_function`: '{SIMILARITY_FUNCTION}' }} }} "
        )

        neo4j_server.execute_query(query, 'str')

INDEX_NODE = 'FunctionModification'
INDEX_NAME = 'retrieve_similar_diff'
INDEX_PROPERTY = 'patchDiffEmbeddings'
SOURCE_PROPERTY = 'patchDiff'

for kb_name, url in zip(kb_names, kb_urls):

    logging.info(f"Adding patch the embeddings for : {kb_name} at {url}")

    neo4j_server = Neo4JServer(
        url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    query = f"MATCH ({NODE_TAG}:{INDEX_NODE}) RETURN ID({NODE_TAG})"
    
    res = neo4j_server.execute_query(query)

    ids = res[f'ID({NODE_TAG})'].to_numpy()

    prop_str = f'{NODE_TAG}.{SOURCE_PROPERTY}'

    for node_id in tqdm(ids):
        query = f"MATCH ({NODE_TAG}:{INDEX_NODE}) WHERE ID({NODE_TAG}) = {node_id} RETURN {prop_str}"
        res = neo4j_server.execute_query(query)

        code = res[prop_str].to_numpy()[0]

        e = get_embeddings(code)

        query = (
            f'MATCH ({NODE_TAG}:{INDEX_NODE}) WHERE ID({NODE_TAG}) = {node_id} '
            f'SET {NODE_TAG}.{INDEX_PROPERTY} = toFloatList({e}) '
            f'RETURN {NODE_TAG}'
        )

        neo4j_server.execute_query(query)

    query = f'DROP INDEX `{INDEX_NAME}`'

    neo4j_server.execute_query(query, 'str')

    # create the index
    query = (
        f"CREATE VECTOR INDEX `{INDEX_NAME}` "
        f"FOR ({NODE_TAG}:{INDEX_NODE}) ON ({NODE_TAG}.{INDEX_PROPERTY}) "
        f"OPTIONS {{ indexConfig: {{ `vector.dimensions`: {EMB_DIMENSION}, `vector.similarity_function`: '{SIMILARITY_FUNCTION}' }} }} "
    )

    neo4j_server.execute_query(query, 'str')

def main():
    pass

# kb_update_embeddings bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7687 bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7688 bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7689 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152



