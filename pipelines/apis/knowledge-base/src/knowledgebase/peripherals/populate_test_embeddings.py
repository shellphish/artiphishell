import logging
import numpy as np
import pandas as pd

from tqdm.auto import tqdm


from ..settings import *
from ..clients.embedding_api_client import EmbeddingsAPI
from ..clients.neo4j_client import Neo4JServer


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

    args = parser.parse_args()

    INDEX_PROPERTY = 'testMethodEmbeddings'
    INDEX_NAME = 'test_method_index'
    INDEX_NODE = 'JenkinsTest'

    neo4j_server = Neo4JServer(
        args.neo4j_bolt_url,
        args.neo4j_username,
        args.neo4j_password,
        args.neo4j_db
    )

    embs_api = EmbeddingsAPI(args.embeddings_api_url, AUTH_KEY)


    query = (
        f"MATCH (n:{INDEX_NODE}) RETURN ID(n), n.method_source"
    )

    res = neo4j_server.execute_query(query)

    ids = res['ID(n)'].to_numpy()
    sources = res['n.method_source'].to_numpy()


    for id,s in tqdm(zip(ids, sources)):
        e = embs_api.get_code_embeddings(s, code_type='function', from_model=DEFAULT_EMBEDDING_MODEL)

        query = (
            f'MATCH (n:{INDEX_NODE}) WHERE ID(n) = {id} '
            f'SET n.{INDEX_PROPERTY} = toFloatList({e.tolist()}) '
            'RETURN n'
        )

        neo4j_server.execute_query(query)

    # create the index
    query = (
        f"CREATE VECTOR INDEX `{INDEX_NAME}` "
        f"FOR (n:{INDEX_NODE}) ON (n.{INDEX_PROPERTY}) "
        f"OPTIONS {{ indexConfig: {{ `vector.dimensions`: {len(e)}, `vector.similarity_function`: '{SIMILARITY_FUNCTION}' }} }} "
    )

    neo4j_server.execute_query(query, 'str')


# kb_populate_test_embeddings bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7687 http://beatty.unfiltered.seclab.cs.ucsb.edu:49152

