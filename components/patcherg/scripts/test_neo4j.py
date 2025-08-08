from neo4j import GraphDatabase

def test_connection():
    query = "MATCH (n:HarnessInputNode)-[COVERS]->(c:CFGFunction) WHERE n.crashing = true RETURN n, c"
    try:
        # Try to connect
        driver = GraphDatabase.driver("bolt://localhost:7687")
        with driver.session() as session:
            # Run a simple query
            result = session.run(query)
            # covert all the records to a list
            records = list(result)
            print(f"Connection successful! Test query returned {len(records)} records.")
            record = records[0]
            cfg = record.get('c')
            harness = record.get('n')
            print(f"Connection successful! Test query returned: {harness} \n {cfg} \n")
            # for record in records:
            #     cfg = record.get('c')
            #     harness = record.get('n')
            #     print(f"Connection successful! Test query returned: {harness} \n {cfg} \n")
        driver.close()
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_connection()