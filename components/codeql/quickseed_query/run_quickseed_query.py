from typing import Dict, List
from pathlib import Path
from jinja2 import Template
import yaml
import argparse


QUERY_TEMPLATES_PATH = Path(__file__).parent / "query_templates"
QUERY_PATH = Path(__file__).parent / "queries"
JAZZER_SINK_METHODS = Path(__file__).parent / "jazzer_sink_methods.yaml"

from libcodeql.client import CodeQLClient

def main():
    parser = argparse.ArgumentParser(description='Run all queries on a database')
    parser.add_argument('--project-name', type=str,  help='The name of the project in codeql database')
    parser.add_argument('--project-id', type=str, help='The id of the project in codeql database')
    parser.add_argument('--output-path', type=Path, help='The path to save the report')
    args = parser.parse_args()
    client = CodeQLClient()
    codeql_report = run_all_query(client, args.project_name, args.project_id)
    with open(args.output_path, 'w') as f:
        yaml.dump(codeql_report, f)
    # try:
        # format_vuln_report(codeql_report)
    # except Exception as e:
        # print(f"Error formatting the report: {e}")

def format_vuln_report(codeql_report:Dict):
    print("Formatting the report")
    import os
    recs = codeql_report["Sinks"]
    new_format = {}
    for k, v in recs.items():
        for r in v:
            try:
                id = r["sink_location"]
                if id not in new_format:
                    new_format[id] = {
                        "id": id,
                        "src": "codeql",
                        "hits": [],
                    }
                parts = id.split(":")
                start_line = parts[2]
                end_line = parts[4]
                new_format[id]["hits"].append(
                    {
                        "type": k,
                        "query": "quickseed.ql",
                        "desc": r["sink_qualified_name"],
                        "endLine": start_line,
                        "startLine": end_line,
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


def run_all_query(client: CodeQLClient, project_name: str, project_id: str, excluding_sanitizers: List=[])-> Dict: #["RegexInjection", "ReflectionCallInjection"]
    codeql_report = {}

    # Query for call graph for sanitizers
    with open(QUERY_TEMPLATES_PATH / "Sanitizer.ql.j2", "r") as f:
        sanitizer_query_template = f.read()
    query_template = Template(sanitizer_query_template)
    with open(JAZZER_SINK_METHODS, "r") as f:
        sink_methods_dict = yaml.safe_load(f)


    # all_sink_methods = []
    # for sanitizer_name, sink_methods in sink_methods_dict.items():
    #     if sanitizer_name in excluding_sanitizers:
    #         continue
    #     all_sink_methods.extend(sink_methods)
    # sanitizer_name = "All"
    # query = query_template.render(
    #     sanitizer_name=sanitizer_name, 
    #     sink_methods=all_sink_methods, 
    #     enumerate = enumerate
    # )
    # query_result = client.query({
    #     "cp_name": project_name,
    #     "project_id": project_id,
    #     "query": query
    # })
    # codeql_report[sanitizer_name] = query_result

    
    # Query for sinks
    with open(QUERY_TEMPLATES_PATH / "Sinks.ql.j2", "r") as f:
        sinks_query_template = f.read()
    query_template = Template(sinks_query_template)
    for sanitizer_name, sink_methods in sink_methods_dict.items():
        if sanitizer_name in excluding_sanitizers:
            continue
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
        if codeql_report.get("Sinks") is None:
            codeql_report["Sinks"] ={}
            codeql_report["Sinks"][sanitizer_name] = query_result
        else:
            codeql_report["Sinks"][sanitizer_name] = query_result

    # # Query for jazzer sinks
    # with open(QUERY_TEMPLATES_PATH / "JazzerSinks.ql.j2", "r") as f:
    #     sinks_query_template = f.read()
    # query_template = Template(sinks_query_template)
    # for sanitizer_name, sink_methods in sink_methods_dict.items():
    #     if sanitizer_name in excluding_sanitizers:
    #         continue
    #     query = query_template.render(
    #         sanitizer_name=sanitizer_name, 
    #         sink_methods=sink_methods, 
    #         enumerate = enumerate
    #     )
    #     query_result = client.query({
    #         "cp_name": project_name,
    #         "project_id": project_id,
    #         "query": query
    #     })
    #     if codeql_report.get("JazzerSinks") is None:
    #         codeql_report["JazzerSinks"] ={}
    #         codeql_report["JazzerSinks"][sanitizer_name] = query_result
    #     else:
    #         codeql_report["JazzerSinks"][sanitizer_name] = query_result

    # Query for last hop to jazzer sink
    with open(QUERY_TEMPLATES_PATH / "LastHopEdges.ql.j2", "r") as f:
        sanitizer_query_template = f.read()
    query_template = Template(sanitizer_query_template)
    # query_results = []
    all_sink_methods = []
    for sanitizer_name, sink_methods in sink_methods_dict.items():
        all_sink_methods.extend(sink_methods)

    query = query_template.render(
        sanitizer_name="All",
        sink_methods=all_sink_methods,
        enumerate=enumerate
    )
    query_result = client.query({
        "cp_name": project_name,
        "project_id": project_id,
        "query": query
    })
    # query_results.extend(query_result)
    codeql_report["LastHopEdges"] = query_result

    # # Other queries
    # for ql_file in QUERY_PATH.iterdir():
    #     with open(ql_file, "r") as f:
    #         query = f.read()
    #     # FIXME: project id
    #     query_result = client.query({
    #         "cp_name": project_name,
    #         "project_id": project_id,
    #         "query": query
    #     })
    #     codeql_report[ql_file.stem] = query_result

    # #standard codeql library queries
    # std_query_dirs = ["CWE-078", "CWE-022", "CWE-918", "CWE-502", "CWE-089", "CWE-643", "CWE-470", "CWE-917", "CWE-090", "CWE-094"]
    # for std_query in std_query_dirs:
    #     query_result = client.analyze({
    #     "cp_name": project_name, 
    #     "project_id": project_id,
    #     "queries": [
    #         "codeql/java-queries:Security/CWE/" + std_query
    #     ]
    #     })
    #     codeql_report[std_query] = query_result

    # experimental_query_dirs = ["CWE-434"]
    # for experimental_query in experimental_query_dirs:
    #     query_result = client.analyze({
    #     "cp_name": project_name, 
    #     "project_id": project_id,
    #     "queries": [
    #         "codeql/java-queries:experimental/Security/CWE/" + experimental_query
    #     ]
    #     })
    #     codeql_report[std_query] = query_result

    return codeql_report

if __name__ == '__main__':
    main()