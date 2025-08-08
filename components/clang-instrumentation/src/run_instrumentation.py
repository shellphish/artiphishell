import argparse
import pathlib
import tempfile
import shutil
import re
import os
import random
from collections import defaultdict

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject, InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation import griller_flag

CP : OSSFuzzProject = None
BITCODE : pathlib.Path = None
OUTPUT_FILE : pathlib.Path = None
FLAGS: str = None

def _build_target(bitcode, flags):
    """
    Build the target with the given bitcode and flags.
    """
    with tempfile.TemporaryDirectory(prefix="/shared/griller-tmp-") as tmp_dir:
        shutil.copy(bitcode, f"{tmp_dir}/griller_prog.bc")
        with open(f"{tmp_dir}/griller_flags.txt", "w") as f:
            f.write(flags)

        os.makedirs(f"{tmp_dir}/final_bin", exist_ok=True)
        build_result = CP.build_target(
            sanitizer="address", 
            extra_files={
                f"{tmp_dir}/griller_prog.bc" : "/grill/griller_prog.bc",
                f"{tmp_dir}/griller_flags.txt" : "/grill/griller_flags.txt",
                f"{tmp_dir}/final_bin" : "/grill/bin",
            }, 
        )
        if os.path.exists(f"{tmp_dir}/final_bin/final_bin"):
            shutil.copy(f"{tmp_dir}/final_bin/final_bin", OUTPUT_FILE)
    return build_result
                            
def setup_project(args):
    global CP, BITCODE, OUTPUT_FILE, FLAGS
    FLAGS = args.flags
    OUTPUT_FILE = args.output_file
    CP = InstrumentedOssFuzzProject(
        project_id = args.project_id,
        oss_fuzz_project_path = args.oss_fuzz_project_path,
        use_task_service = False, # always spwan a new container on the same host
        instrumentation = griller_flag.GrillerFlagInstrumentation()
    )
    
    if args.local_run:
        print("[LOCAL_RUN] Building the builder and runner images...\n")
        CP.build_builder_image()
        CP.build_runner_image()
        

    # find first .bc file in the artifacts directory, non-recursive
    assert args.bitcode.is_file(), f"Bitcode file {args.bitcode} does not exist"
    BITCODE = args.bitcode

def main():
    # Load OSSFuzz project    
    setup_project(args())
    build_result = _build_target(BITCODE, FLAGS)
    print("[BUILD_RESULT] ", build_result.stderr)


def args():
    parser = argparse.ArgumentParser(description="Get Compiler Flags")
    parser.add_argument('--project_id', required=True, type=pathlib.Path)
    parser.add_argument('--oss_fuzz_project_path', required=True, type=pathlib.Path)
    parser.add_argument("--local_run", action="store_true", help="Run locally", default=False)
    parser.add_argument("--bitcode", required=True, type=pathlib.Path)
    parser.add_argument("--flags", required=True, type=str)
    parser.add_argument("--output_file", required=True, type=pathlib.Path)

    return parser.parse_args()

if __name__ == "__main__":
    main()