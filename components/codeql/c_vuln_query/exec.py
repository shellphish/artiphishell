import subprocess
import os
import tempfile
import json
import time
import yaml
import pathlib

yaml.Dumper.ignore_aliases = lambda *args: True

import analyze

SCRIPT_PATH = pathlib.Path(__file__).parent.resolve()

if __name__ == "__main__":
    start = time.time()
    ana = analyze.Analyzer(
        project_id=os.environ.get("PROJECT_ID","1"),
        db_name=os.environ.get("PROJECT_NAME","nginx"),
        use_cache=True
    )
    res = ana.run_query_group("custom")
    print("Filtered", len(res), "functions.")
    
    res_location = os.environ.get("CODEQL_VULN_REPORT", "")

    with open(res_location, "w") as f:
        yaml.safe_dump(res, f, default_flow_style=False)
    print("Took", time.time() - start, "s")
