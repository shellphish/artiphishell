#!/usr/bin/env python3

import sys
from neomodel import db, config, NeomodelException
from analysis_graph.models.cfg import CFGFunction
# Import related models for clarity, even if not directly used in the final query filter
from analysis_graph.models.harness_inputs import HarnessInputNode
from analysis_graph.models.grammars import Grammar

def get_covered_functions():
    """
    Connects to the Neo4j database (implicitly via library setup)
    and retrieves all covered CFGFunction nodes.

    Returns:
        A list of CFGFunction objects representing the covered functions.
        Returns an empty list if connection fails or no functions are found.
    """
    try:
        print("Querying for covered functions using Cypher...")

        # Define the raw Cypher query
        query = """
        MATCH (f:CFGFunction)
        WHERE EXISTS((:HarnessInputNode)-[:COVERS]->(f)) OR EXISTS((:Grammar)-[:COVERS]->(f))
        RETURN f
        """

        # Execute the query
        results, meta = db.cypher_query(query)

        # Inflate the results back into CFGFunction node objects
        covered_functions = [CFGFunction.inflate(row[0]) for row in results]

        print(f"Query executed.")

        return covered_functions

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return []

def main():
    """
    Connects to the database (implicitly), fetches covered functions,
    and prints their identifiers.
    """
    covered_functions_list = get_covered_functions()

    if covered_functions_list:
        print(f"\nFound {len(covered_functions_list)} covered functions:")
        for func in covered_functions_list:
            # CFGFunction identifier is usually a unique key representing the function
            print(f"  - {func.identifier}")
            # You could also print other attributes like:
            # print(f"  - Name: {func.function_name}, File: {func.filepath}")
    else:
        print("\nNo covered functions found or error occurred during retrieval.")

if __name__ == "__main__":
    main() 