#! /usr/bin/env python3

import re
import subprocess
import json
import argparse

ignore_list = [
    'oss_fuzz_project_build.project_build_artifacts',
    'oss_fuzz_project_build.project_run_artifacts',
    'oss_fuzz_project_run.project_volumes_id',
    'aflrun_build.aflrun_build_artifacts',
    'patcherq.patched_artifacts_dir'
    'patcherq_from_sarif.patched_artifacts_dir',
    'aflpp_fuzz_merge.benigns_dir',
    'coverage_trace.benign_harness_inputs',
    'coverage_trace.benign_harness_inputs_metadata',
    'jazzer_fuzz_merge.benign_harness_inputs',
    'discovery_guy_from_bypass_request.patched_artifact',
]

ignore_patterns = [
    r'.*patched_artifacts_dir.*',
]


def get_all_repos():
    res = subprocess.check_output(["pd","status","-j"])
    data = json.loads(res)

    repos = []
    for k,rs in data.items():
        for rn in rs.keys():
            rkey = f"{k}.{rn}"
            if rkey in ignore_list:
                continue
            try:
                if any(re.match(p, rkey) for p in ignore_patterns):
                    continue
            except Exception as e:
                print(f"Error matching pattern for {rkey}: {e}")
            repos.append(rkey)
    return repos

def run_backup(args):
    if args.skip_artifacts:
        ignore_patterns.append(r'.*build_artifact.*')
        ignore_patterns.append(r'.*base_artifacts.*')
        ignore_patterns.append(r'.*run_artifact.*')

    bdir = args.backup_dir
    repos = get_all_repos()
    subprocess.check_call(["mkdir","-p",bdir])
    print(repos)
    subprocess.check_call(["pd","backup",bdir, *repos])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("backup_dir", type=str)
    parser.add_argument("--skip-artifacts", action="store_true", help="Skip artifacts in the backup", required=False)
    args = parser.parse_args()
    run_backup(args)


