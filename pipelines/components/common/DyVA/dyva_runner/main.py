
import argparse
import yaml
import time
import os

from typing import List
from pathlib import Path
from universal_dbg import engine

import dyva_build

def get_args():
    argparser = argparse.ArgumentParser(description='invguy-build')

    argparser.add_argument('--target-metadata', type=Path, help='Target metadata', required=True)
    argparser.add_argument('--target-dir', type=Path, help='Target program source code', required=True)
    argparser.add_argument('--harness-info', type=Path, help='Target harness info', required=True)
    argparser.add_argument("--poi-report", type=Path, default="poi_report", help="Path to poi_report", required=True)
    argparser.add_argument("--crashing-input", type=Path, help="Path to crashing input", required=True)
    argparser.add_argument("--function-indices", type=Path, help="Path to function indices folder", required=True)
    argparser.add_argument("--function-json", type=Path, help="Path to function json file", required=True)
    argparser.add_argument("--output-path", type=Path, help="Path to output_path", required=True)

    args = argparser.parse_args()
    return args

def main():
    args = get_args()
    docker_tag = dyva_build.build_and_run(args.target_dir, args.target_metadata, args.harness_info, args.crashing_input)
    
    source_dir = args.target_dir / "src"
    socket_path = args.target_dir / "src" / "gdb.socket"
    while not socket_path.exists():
        print(f"waiting for the socket at {socket_path=}")
        time.sleep(1)
    with args.harness_info.open("r") as f:
        harness_info = yaml.safe_load(f)
    os.chdir(args.target_dir / Path(harness_info["cp_harness_source_path"]).parent)
    engine.main.main(args.crashing_input, 
                     source_dir, 
                     args.target_dir / harness_info["cp_harness_binary_path"], 
                     args.output_path, 
                     args.poi_report, 
                     args.function_indices,
                     args.function_json,
                     is_argv=True, 
                     remote=f"{str(socket_path)}")

if __name__ == '__main__':
    main()