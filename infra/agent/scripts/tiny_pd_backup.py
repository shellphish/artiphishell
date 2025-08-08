#! /usr/bin/env python3

import re
import subprocess
import json
import argparse

include_list = [
    'build_configuration_splitter.target_split_metadata_path',
    'build_configuration_splitter.build_configurations_dir',
    'code_swipe.codeswipe_rankings',
    'code_swipe_delta.codeswipe_rankings',
    'debug_build.logs',
    'diff_mode_create_analysis_source.analysis_source',
    'diffguy.diffguy_reports',
    'povguy.pov_report_path',
    'povguy.crashing_input_path',
    'povguy.crashing_input_metadata_path',
    'povguy_delta.pov_report_path',
    'povguy.losan_pov_report_path',
    'semgrep_analysis.semgrep_analysis_vulnerable_functions',
    'run_codechecker.locs_of_interest',
    'run_codechecker.funcs_of_interest',
    'poiguy.poi_report',
    'kumushi_java.kumushi_output',
    'kumushi_delta_java.kumushi_output',
    'kumushi_delta.kumushi_output',
    'kumushi.kumushi_output',
    'harness_info_splitter.project_harness_infos_dir',
    'harness_info_splitter.project_harness_only_metadatas_dir',
    'dyva_agent.dyva_report',
    'quickseed_codeql_query.quickseed_codeql_report',
]

include_patterns = [
    r'pipeline_input.*',
    r'submitter.*',
    r'.*done',
    r'.*logs',
]

ignore_list = [
    'oss_fuzz_project_run.logs',
]
ignore_patterns = [
]


def get_all_repos():
    res = subprocess.check_output(["pd","status","-j"])
    data = json.loads(res)

    repos = []
    for k,rs in data.items():
        for rn in rs.keys():
            rkey = f"{k}.{rn}"
            is_included = False
            if rkey in include_list:
                is_included = True
            else:
                for p in include_patterns:
                    if re.match(p, rkey):
                        is_included = True

            if not is_included:
                continue

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
    bdir = args.backup_dir
    repos = get_all_repos()
    subprocess.check_call(["mkdir","-p",bdir])
    subprocess.check_call(["pd","backup",bdir, *repos])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("backup_dir", type=str)
    args = parser.parse_args()
    run_backup(args)


