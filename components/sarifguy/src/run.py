import os
import argparse
import logging
import yaml

from enum import Enum
from pathlib import Path
from IPython import embed

from sarifguy.sarifguy import main as sarifguy_main

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]")

log = logging.getLogger("sarifguy")
logger = log

log.setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser()
    
    # These are common between dumb and reasonable modes
    parser.add_argument("--sarif-path", type=Path, help="SARIF report file path", required=True)
    parser.add_argument("--out-path", type=Path, help="The output file path where to put the results", required=True)
    parser.add_argument("--sarifguy_heartbeat_path", type=Path, help="Path to the heartbeat file for sarifguy", required=True)
    parser.add_argument("--sarif-meta", type=Path, help="SARIF report metadata", required=True)
    parser.add_argument("--project-name", type=str, help="Project name", required=True)
    parser.add_argument("--mode", type=str, choices=['dumb', 'reasonable'], required=True)
    parser.add_argument("--oss-fuzz-project", type=Path, help="Path to the OSS-Fuzz project", required=True)
    parser.add_argument("--oss-fuzz-project-src", type=str, help="Sources directory of the OSS-Fuzz project", required=True)
    parser.add_argument("--local-run", required=True)

    # These are just for reasonable mode (because we want to get a function resolver)
    #parser.add_argument("--aggregated-harness-info", type=Path, required=False)
    parser.add_argument("--functions-index", type=str, required=False, help="Build directory of the OSS-Fuzz project")
    parser.add_argument("--functions-jsons-dir", type=str, required=False, help="Function jsons directory of the OSS-Fuzz project")

    args = parser.parse_args()

    my_args = dict()
    my_args["sarif_meta"] = args.sarif_meta
    my_args["sarif_path"] = args.sarif_path
    my_args["out_path"] = args.out_path
    my_args["sarifguy_heartbeat_path"] = args.sarifguy_heartbeat_path
    my_args["mode"] = args.mode
    my_args["project_name"] = args.project_name
    my_args["oss_fuzz_project"] = args.oss_fuzz_project
    my_args["oss_fuzz_project_src"] = args.oss_fuzz_project_src
    my_args["local_run"] = args.local_run

    if args.mode == "reasonable":
        #my_args["aggregated_harness_info"] = args.aggregated_harness_info
        my_args["functions_index"] = args.functions_index
        my_args["functions_jsons_dir"] = args.functions_jsons_dir

    sarifguy_main(**my_args)


if __name__ == '__main__':
    main()
