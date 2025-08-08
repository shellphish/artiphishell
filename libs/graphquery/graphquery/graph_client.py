import logging
import os
from urllib.parse import urlparse
from typing import List
from neo4j import GraphDatabase, Record
from neo4j.exceptions import ServiceUnavailable, AuthError, Neo4jError

_l = logging.getLogger(__name__)

class GraphClient:
    def __init__(self, query: str, return_params: List[str] = None):
        bolt_url_with_auth = os.environ.get("ANALYSIS_GRAPH_BOLT_URL", None)
        if os.getenv('CRS_TASK_NUM'):
            bolt_url_with_auth = bolt_url_with_auth.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
        else:
            if 'TASKNUM' in bolt_url_with_auth:
                raise ValueError("Env CRS_TASK_NUM is not set but ANALYSIS_GRAPH_BOLT_URL contains TASKNUM")
        if bolt_url_with_auth is None:
            raise ValueError("BOLT URL not set")
        # Parse the URL to extract credentials
        parsed_url = urlparse(bolt_url_with_auth)

        # Extract username and password
        auth_part = parsed_url.netloc.split('@')[0]
        username, password = auth_part.split(':')

        # Extract host and port
        host_part = parsed_url.netloc.split('@')[1]

        # Reconstruct the URL without auth
        bolt_url = f"{parsed_url.scheme}://{host_part}"

        self.driver = GraphDatabase.driver(bolt_url, auth=(username, password))

        self.query = query
        self.return_params = return_params

    def _connect_to_neo4j(self) -> bool:
        try:
            # Verify connectivity
            self.driver.verify_connectivity()
            _l.info("Connected to Neo4j")
            return True
        except ServiceUnavailable as e:
            print(f"Neo4j service is unavailable: {e}")
        except AuthError as e:
            print(f"Authentication failed: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        return False

    def _query_neo4j(self, timeout_seconds=60, **kwargs) -> list[Record] | list[dict]:
        if self._connect_to_neo4j():
            try:
                with self.driver.session() as session:
                    result = session.run(self.query, timeout=timeout_seconds, **kwargs)
                    records = list(result)
                    if len(records) == 0:
                        _l.info("No records found in the analysis graph")
                        return []
                    _l.info(f"Found {len(records)} records in the analysis graph")
                    _l.info(f"The result contains {records[0].keys()} keys)")
                return records
            except Neo4jError:
                _l.error("Neo4j query failed")
            except Exception as e:
                _l.error(f"An unexpected error occurred while querying Neo4j: {e}")
        self.close()
        return []

    def close(self):
        self.driver.close()

    def execute_query(self, **kwargs) -> list[Record] | dict[str, list]:
        """
        Execute the Cypher query and return the results.
        :return: A list of records returned by the query. if self.return_params is not None, it returns a dict with param as key and a list of node as value.
        """

        return self._query_neo4j(**kwargs)

    @classmethod
    def from_query(cls, query: str, return_params: List[str] = None):
        """
        Create a GarphClient instance from a query string and return parameters.
        :param query: The Cypher query string to execute.
        :param return_params: A list of parameters to return from the query.
        :return: An instance of GarphClient.
        """
        return cls(query, return_params)
