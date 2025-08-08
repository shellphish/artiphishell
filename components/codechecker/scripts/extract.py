#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

def get_locs(report: Path):
    report_path = report / "report_parsed.json"
    data  = json.loads(report_path.read_text())
    return list(set([f"{r['file']}:{r['line']}" for r in data]))

def get_funcs(report: Path):
    report_path = report / "report_parsed.json"
    data = json.loads(report_path.read_text())
    return list(set([r["function"] for r in data if r.get("function") is not None]))

parser = argparse.ArgumentParser(description='Extract functions from reports')
parser.add_argument('--report', type=Path, help='Report file or directory', required=True)
parser.add_argument('--funcs-output', type=Path, help='Output file for functions', required=True)
parser.add_argument('--locs-output', type=Path, help='Output file for locations', required=True)
args = parser.parse_args()

with open(args.funcs_output, 'w') as f:
    f.write("\n".join(get_funcs(args.report)))

with open(args.locs_output, 'w') as f:
    f.write("\n".join(get_locs(args.report)))
