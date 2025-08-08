from typing import Dict, List
from pathlib import Path
from jinja2 import Template
import yaml
import argparse
import os
from shellphish_crs_utils.models.symbols import SourceLocation


QUERY_TEMPLATES_PATH = Path(__file__).parent
QUERY_PATH = Path(__file__).parent / "queries"
JAZZER_SINK_METHODS = Path(__file__).parent.parent / "quickseed_query" / "jazzer_sink_methods.yaml"

from libcodeql.client import CodeQLClient

def main():
    parser = argparse.ArgumentParser(description='Run all queries on a database')
    parser.add_argument('--project-name', type=str,  help='The name of the project in codeql database')
    parser.add_argument('--project-id', type=str, help='The id of the project in codeql database')
    args = parser.parse_args()
    client = CodeQLClient()
    codeql_report = run_all_query(client, args.project_name, args.project_id)

def run_all_query(client: CodeQLClient, project_name: str, project_id: str, excluding_sanitizers: List=[])-> Dict: #["RegexInjection", "ReflectionCallInjection"]
    codeql_report = {}

    # Query for call graph for sanitizers
    with open(QUERY_TEMPLATES_PATH / "FunctionsCallingSinks.ql.j2", "r") as f:
        sanitizer_query_template = f.read()
    query_template = Template(sanitizer_query_template)
    with open(JAZZER_SINK_METHODS, "r") as f:
        sink_methods_dict = yaml.safe_load(f)

    all_results = {}
    for sanitizer_name, sink_methods in sink_methods_dict.items():
        query = query_template.render(
            sanitizer_name=sanitizer_name, 
            sink_methods=sink_methods, 
            enumerate = enumerate
        )
        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })

        all_results[sanitizer_name] = query_result

    print("Raw query result")
    print(query_result)

    print("Formatting the report")
    recs = all_results
    new_format = {}
    for k, v in recs.items():
        for r in v:
            try:
                id = r["sink_location"]
                name = r["sink_qualified_name"]
                parts = id.split(":")
                if id not in new_format:
                    new_format[id] = {
                        "id": id,
                        "src": "codeql",
                        "location": SourceLocation(
                            full_file_path=Path(parts[1]),
                            file_name=Path(parts[1]).name,
                            line_number=int(parts[2]),
                            function_name=name,
                        ).model_dump(mode='json'),
                        "hits": [],
                    }
                start_line = parts[2]
                end_line = parts[4]
                new_format[id]["hits"].append(
                    {
                        "type": k,
                        "query": "quickseed.ql",
                        "desc": r["sink_qualified_name"],
                        "endLine": start_line,
                        "startLine": end_line,
                        "location": SourceLocation(
                            full_file_path=Path(parts[1]),
                            file_name=Path(parts[1]).name,
                            line_number=int(parts[2]),
                            function_name=name
                        ).model_dump(mode='json'),
                        "additionalInfo": {},
                    }
                )
            except Exception as e:
                print(f"Error: {e}")
                print(f"Record: {r}")
                raise
    new_format = [new_format[k] for k in new_format.keys()]
    res_location = os.environ.get("CODEQL_VULN_REPORT", "")
    with open(res_location, "w") as f:
        yaml.dump(new_format, f, default_flow_style=False)


    return codeql_report

if __name__ == '__main__':
    main()