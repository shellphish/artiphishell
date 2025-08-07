import logging
import neo4j

from neo4j import GraphDatabase
from neo4j.exceptions import DriverError, Neo4jError
from neomodel import config as neoconfig

from ..settings import *


# To interact with Neo4J server
class Neo4JServer:
    def __init__(self, uri, user, password, database=None):
        logging.info(f'Neo4J URI: {uri}')
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database
        self.return_types = {'pd':neo4j.Result.to_df, 'str': lambda x: str(x)}
        self.default_return_type = ('pd',neo4j.Result.to_df)
        neoconfig.DRIVER = self.driver

    def execute_query(self, query, return_type='pd'):

        if return_type not in self.return_types:
            logging.warning(f'Return type: {return_type} is not recognized, defaulting to {self.default_return_type[0]}')

        transformer = self.return_types.get(return_type, self.default_return_type[1])

        try:
            record = self.driver.execute_query(query, database_=self.database, result_transformer_=transformer)
            return record
        # Capture any errors along with the query and data for traceability
        except (DriverError, Neo4jError) as exception:
            logging.error("%s raised an error: \n%s", query, exception)
            return None 

    def create_vector_index(self, index_name, node_type, property_name, emb_size):
        sim_function = SIMILARITY_FUNCTION

        assert sim_function in ['cosine', 'euclidean'], "Similarity function has to be 'cosine' or 'euclidean', aborting"

        query = (
            f"CREATE VECTOR INDEX `{index_name}` "
            f"FOR (n:{node_type}) ON (n.{property_name}) "
            f"OPTIONS {{ indexConfig: {{ `vector.dimensions`: {emb_size}, `vector.similarity_function`: '{sim_function}' }} }} "
        )
        self.execute_query(query, 'str')

    def get_vector_index_info(self):
        query = 'SHOW VECTOR INDEXES YIELD name, labelsOrTypes, properties, options'
        return self.execute_query(query)
    
    # Don't forget to close the driver connection when you are finished with it
    def __del__(self):
        if hasattr(self, 'driver'):
            self.driver.close()
