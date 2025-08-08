import unittest
import logging
from graphquery.graph_client import GarphClient

def pytest_configure():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

class QueryTest(unittest.TestCase):
    def setUp(self):
        self.query = "MATCH (n:HarnessInputNode) <-- (p:PoVReportNode) return n, p LIMIT 25"
        self.return_params = ["n", "p"]
        pytest_configure()
        self.client = GarphClient(self.query, self.return_params)

    def test_connect_to_neo4j(self):
        result = self.client._connect_to_neo4j()
        self.assertTrue(result, "Failed to connect to Neo4j")

    def test_query_neo4j(self):
        results = self.client._query_neo4j(self.query)
        logging.log(logging.INFO, f"Query results: {results}")
        self.assertIsInstance(results, list | dict, "Query did not return a list")
        self.assertGreater(len(results), 0, "Query returned no records")