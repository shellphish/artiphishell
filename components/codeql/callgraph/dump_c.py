#!/usr/bin/env python3
# This is a wrapper for dumping codeql query results for quickseed (ported from discoveryguy)

from callgraph_c import BetterCallGraph
import os
import yaml
import sys
# Get the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path
sys.path.append(parent_dir)
from c_vuln_query.analyze import Analyzer

print("Import OK")
if __name__ == "__main__":
    CP_NAME = os.environ.get("PROJECT_NAME")
    PROJ_ID = os.environ.get("PROJECT_ID")
    OUTPUT = os.environ.get("QUICKSEED_CODEQL_REPORT", "callgraph_dumped.yaml")
    cg = BetterCallGraph(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
    ana = Analyzer(
        project_id=PROJ_ID,
        db_name=CP_NAME,
        use_cache=True
    )
    with open(OUTPUT, 'w') as f:
        yaml.safe_dump({
            "callgraph": cg.get_all_callees(),
            "sinks": ana.run_query_group("custom")
        }, f, indent=4)