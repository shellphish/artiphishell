#!/usr/bin/env python3

import os
import json
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description='Parse CodeChecker output')
parser.add_argument('input', type=str, help='CodeChecker output json file')
parser.add_argument('--clang-indexer-dir', type=str, help='Clang indexer directory')

args = parser.parse_args()

with open(args.input, 'r') as f:
    data = json.load(f)

assert data['version'] == 1
reports = data['reports']

# NOTE: 2025-03-26T16:23:00-0700: silipwn: Hardcoded for the AFLRUN output
# If report is empty, warn and dump all the functions
if not reports:
    results = []
    for root, dirs, files in os.walk(args.clang_indexer_dir):
        for file in files:
            if file.endswith('.json'):
                with open(os.path.join(root, file)) as fp:
                    data = json.load(fp)
                    results.append({
                        'file': data['filename'],
                        'function': data['funcname'],
                        'line': data['start_line'],
                    })
    print(json.dumps(results))
    exit(0)

high_severity_reports = [r for r in reports if r['severity'] == 'HIGH']

results = []

for report in high_severity_reports:
    results.append(
        {
            'file': report['file']['path'],
            'line': report['line'],
            'column': report['column'],
            'checker': report['checker_name'],
            'message': report['message'],
            'analyzer_name': report['analyzer_name']
        }
    )


if args.clang_indexer_dir:
    clang_dir = Path(args.clang_indexer_dir)
    assert clang_dir.exists(), f'Clang indexer directory {clang_dir} does not exist'

    functions = []
    for func_dir in clang_dir.rglob('FUNCTION'):
        if not func_dir.is_dir():
            continue
        for f in func_dir.glob('*.json'):
            with open(f) as fp:
                data = json.load(fp)
                functions.append({
                    'start_line': data['start_line'], 
                    'end_line': data['end_line'],
                    'funcname': data['funcname'],
                    'filename': data['filename']
                })

    for result in results:
        fname = os.path.basename(result['file'])
        result['function'] = next(
            (f['funcname'] for f in functions 
             if f['filename'] == fname 
             and f['start_line'] <= result['line'] <= f['end_line']),
            None
        )

print(json.dumps(results))
