import logging
import os
import pandas as pd

from ..settings import *
from ..clients.neo4j_client import Neo4JServer

class SchemaRetriever:
    def __init__(self, neo4j:Neo4JServer):

        self.neo4j = neo4j
    
    # all unique node types
    # example output format (pandas)
    '''
    NodeType
    Commit
    CVE
    Commit

    '''
    def retrieve_unique_node_types(self):
        query = (
            "MATCH (n) "
            "WITH DISTINCT LABELS(n) AS N "
            "RETURN N[0] AS NodeType" 
        )
         
        df:pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')

        return df.to_json(orient='records')
    

    # all unique relationships between our node types
    # example output format (pandas)
    '''
    Left_NodeType      RelationshipType           Right_NodeType
    Commit          Author              Actor
    CVE             ASSIGNED_BY         Assigner
    Commit          MODIFIED_FILE       SourceFile

    '''
    def retrieve_unique_relationships(self):

        query = (
            "MATCH (n)-[x]->(m) "
            "WITH DISTINCT LABELS(n) AS L, TYPE(x) AS RelationshipType, LABELS(m) AS R "
            "RETURN L[0] AS Left_NodeType, RelationshipType, R[0] AS Right_NodeType"
        )

        df:pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')

        return df.to_json(orient='records')


    # all unique relationships between our node types
    # example output format (pandas)
    '''
    NodeType                   UniqueProperties
    JenkinsAdvisory             ["advisory_name", "advisory_id", "url", "date"]
    Actor                       ["name", "email"]
    '''
    def retrieve_nodes_and_properties(self):
        query = (
            "MATCH (n) " 
            "WITH DISTINCT LABELS(n) AS NodeType, KEYS(n) AS AllProperties "
            "WITH REDUCE(s = [], prop IN COLLECT(AllProperties) |  s + prop) AS ConcatProperties, NodeType "
            "WITH REDUCE(s = [], prop IN ConcatProperties | CASE WHEN prop in s THEN s ELSE s+prop END) AS UniqueProperties, NodeType[0] AS NodeType "
            "RETURN NodeType, UniqueProperties"
        )

        df:pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')
        return df.to_json(orient='records')

    
    def retrieve_index_types(self):

        query = (
            "SHOW VECTOR INDEXES YIELD name, labelsOrTypes, properties "
            "RETURN name AS RetrievalIndex, labelsOrTypes[0] AS RetrievalNodeType, properties[0] AS RetrievalNodeProperty"
        )

        df:pd.DataFrame = self.neo4j.execute_query(query, return_type='pd')
        return df.to_json(orient='records')

def main():

    logging.basicConfig(level=logging.INFO)
    logging.info('Schema retrieval API Server Started.')

    import argparse

    parser = argparse.ArgumentParser(description='API for retrieving information about our knowledge-base Neo4J database schema')
    parser.add_argument('neo4j_bolt_url', help='Bolt URL for the Neo4J server')
    parser.add_argument('--neo4j-username', help='Username for the Neo4J server', default='neo4j')
    parser.add_argument('--neo4j-password', help='Password for the Neo4J server', default=AUTH_KEY)
    parser.add_argument('--neo4j-db', help='Database name for the Neo4J server', default='neo4j')

    parser.add_argument('--request', help='what to retrieve info about Neo4J schema', choices=["nodes", "relationships", "properties", "indexes"], default="nodes")

    args = parser.parse_args()

    p = os.path.dirname(os.path.realpath(__file__))
    # read the API configuration -- hosts, ports etc.

    try:
        neo4j_server = Neo4JServer(
            args.neo4j_bolt_url,
            args.neo4j_username,
            args.neo4j_password,
            args.neo4j_db
        )

        retriever = SchemaRetriever(neo4j_server)

        if args.request == 'nodes':
            res = retriever.retrieve_unique_node_types()
        elif args.request == 'relationships':
            res = retriever.retrieve_unique_relationships()
        elif args.request == 'properties':
            res = retriever.retrieve_nodes_and_properties()
        elif args.request == 'indexes':
            res = retriever.retrieve_index_types()
        else:
            logging.error(f'Request: {args.request} is not recognized')
            res = ''

        # this will be returned to the client in a HTTP response as JSON
        logging.info('\n'+res+'\n')       

    except:
        logging.error("Exception ",exc_info=1)

# kb_schema_api bolt://beatty.unfiltered.seclab.cs.ucsb.edu:7687 --request indexes