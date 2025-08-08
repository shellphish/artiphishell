import argparse
from pathlib import Path
import yaml

from libcodeql.client import CodeQLClient
from QuickSeed.utils import run_all_query

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

if __name__ == '__main__':
    main()