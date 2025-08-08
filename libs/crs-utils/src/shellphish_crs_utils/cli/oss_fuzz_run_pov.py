import argparse
from collections import defaultdict
import os
import glob
from pathlib import Path
import sys

import rich
from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "dynamic_analysis", "oss_fuzz.run_pov")
tracer = get_otel_tracer()

def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description='Build instrumented projects')
    parser.add_argument('target_path', type=Path, help='Path to the oss-fuzz project directory')
    parser.add_argument('--build-runner-image', action='store_true', help='Build the runner image')
    parser.add_argument('--use-task-service', action='store_true', help='Use the pipeline task service to run the pov')
    parser.add_argument('--project-id', type=str, help='Project ID to use for the build', default=None)
    parser.add_argument('--timeout', type=int, help='Timeout for the run_pov command', default=60)
    parser.add_argument('--sanitizer', type=str, help='Sanitizer to apply', choices=['none', 'address', 'memory', 'undefined', 'coverage'], required=True)
    parser.add_argument('--instrumentation', type=str, help='Instrumentation to apply', choices=SUPPORTED_INSTRUMENTATIONS.keys(), required=True)
    parser.add_argument('-o', '--run-pov-output-path', type=Path, help='Path to store the output of the run_pov command', default=None)
    parser.add_argument('harness_name', type=str, help='Name of the harness to fuzz')
    parser.add_argument('input_path', type=Path, help='Path to the input file')
    # parser.add_argument('--instance-name', type=str, help='Name of the instance to run', required=True)
    args = parser.parse_args()

    with tracer.start_as_current_span("oss_fuzz.run_pov") as span:
        span.set_attribute("crs.action.target.harness", args.harness_name)
        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]
        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            args.target_path,
            project_id=args.project_id,
            use_task_service=args.use_task_service,
        )
        if args.build_runner_image:
            instr_project.build_runner_image()

        # import ipdb; ipdb.set_trace()
        result = instr_project.run_pov(
            args.harness_name,
            data_file=args.input_path,
            sanitizer=args.sanitizer,
            timeout=args.timeout,
        )

        if args.run_pov_output_path is not None:
            with open(args.run_pov_output_path, 'w') as f:
                f.write(result.model_dump_json(indent=2))
        span.add_event("pov_run", {"result": result.model_dump_json(indent=2)})
        # rich.print(result)
        print(f"RunPoV {'succeeded' if result.task_success else 'failed'}!")
        print(f"Output directory: {result.out_dir}")

        if result.task_success:
            sys.exit(0)
        else:
            sys.exit(1)
