import argparse
import os
import glob
import sys
import time 
import hashlib
from pathlib import Path
from collections import defaultdict

from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "dynamic_analysis", "oss_fuzz.run_custom")
tracer = get_otel_tracer()

def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description='Build instrumented projects')
    parser.add_argument('target_path', type=Path, help='Path to the oss-fuzz project directory')
    parser.add_argument('--use-task-service', action='store_true', help='Use the pipeline task service to run the command in the container')
    # parser.add_argument('--project-id', type=str, help='Project ID to use for the run', required=False, default=None)
    # parser.add_argument('-d', '--docker-args', type=str, help='Extra arguments to pass to the docker command', action='append', default=[])
    parser.add_argument('--image', type=str, help='Docker image to use', default='runner')
    parser.add_argument('--instrumentation', type=str, help='Instrumentation to apply', choices=SUPPORTED_INSTRUMENTATIONS.keys(), required=True)
    parser.add_argument('cmd', type=str, help='command to run in the oss-fuzz container')
    args = parser.parse_args()

    with tracer.start_as_current_span("oss_fuzz.run_custom") as span:
        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]
        
        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            args.target_path,
            use_task_service=args.use_task_service,
        )

        # Genereate a temporary file where we are gonna store the command
        command_file_name = f"cmd_{int(time.time())}_{hashlib.sha1(os.urandom(32)).hexdigest()}.sh"
        command_file = args.target_path / "artifacts" / "work" / command_file_name
        with open(command_file, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(args.cmd)

        print(f"Command file at {command_file}")

        # Chmod it 
        os.system(f"chmod +x {command_file}")
        
        if args.image == 'runner':
            result = instr_project.runner_image_run(
                f"/work/{command_file_name}",
            )
        elif args.image == 'builder':
            result = instr_project.builder_image_run(
                f"/work/{command_file_name}",
            )
        else:
            raise ValueError(f"Unknown image type {args.image}")

        span.add_event("custom_command", {"result": result.model_dump_json(indent=2)})
        print(result)

        print(f"Output directory: {result.out_dir}")
        
        # Clean
        os.system(f"rm {command_file}")

        if result.task_success:
            sys.exit(0)
        else:
            sys.exit(1)
