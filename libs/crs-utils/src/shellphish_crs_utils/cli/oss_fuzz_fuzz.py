import argparse
import os
import glob
import sys

from collections import defaultdict
from pathlib import Path

from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.instrumentation.aflpp import AFLPPInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.aijon import AIJONInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.aflrun import AFLRunInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.builtins import BuiltinLibfuzzerInstrumentation, BuiltinAFLInstrumentation, BuiltinHonggfuzzInstrumentation, BuiltinCentipedeInstrumentation
from shellphish_crs_utils.oss_fuzz.instrumentation.jazzer import JazzerInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject, OSSFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "fuzzing", "oss_fuzz.fuzz")
tracer = get_otel_tracer()

def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description='Build instrumented projects')
    parser.add_argument('target_path', type=Path, help='Path to the oss-fuzz project directory')
    parser.add_argument('harness_name', type=str, help='Name of the harness to fuzz')
    parser.add_argument('--build-runner-image', action='store_true', help='Build the runner image')
    parser.add_argument('--use-task-service', action='store_true', help='Use the pipeline task service to run the fuzzer')
    parser.add_argument('--sanitizer', type=str, help='Sanitizer to apply', choices=['none', 'address', 'memory', 'undefined', 'coverage'], required=True)
    parser.add_argument('--instrumentation', type=str, help='Instrumentation to apply', choices=SUPPORTED_INSTRUMENTATIONS.keys(), required=True)
    parser.add_argument('--sync-dir', type=Path, help='Path to the   sync directory', default='/shared/fuzzer_sync/oss-fuzz-fuzz')
    parser.add_argument('--instance-name', type=str, help='Name of the instance to run', required=True)
    parser.add_argument('--skip-seed-corpus', action='store_true', help='Do not use the target-provided input corpus.')
    parser.add_argument('--skip-dictionary', action='store_true', help='Do not use the target-provided dictionaries.')
    parser.add_argument('-d', '--docker-args', type=str, help='Extra arguments to pass to the docker command', action='append', default=[])
    parser.add_argument('-e', '--extra-env', type=str, help='Extra environment variables to pass to the docker command', action='append', default=[])
    args = parser.parse_args()

    with tracer.start_as_current_span("oss_fuzz.fuzz") as span:
        span.set_attribute("crs.action.target.harness", args.harness_name)
        os.makedirs(args.sync_dir, exist_ok=True)

        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]
        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            args.target_path,
            use_task_service=args.use_task_service,
        )
        instr_project.build_runner_image()

        # result = instr_project.fuzz_harness__local(
        # import ipdb; ipdb.set_trace()
        result = instr_project.fuzz_harness(
            args.harness_name,
            sync_dir=args.sync_dir,
            instance_name=args.instance_name,
            extra_docker_args=args.docker_args,
            skip_seed_corpus=args.skip_seed_corpus,
            skip_dictionary=args.skip_dictionary,
            extra_env=dict([tuple(v.split("=", 1)) for v in args.extra_env]),
        )

        span.add_event("fuzzing_run", {"result": result.model_dump_json(indent=2)})
        print(result)
        print(f"Fuzzing {'succeeded' if result.task_success else 'failed'}!")
        print(f"Output directory: {result.out_dir}")

        if result.task_success:
            sys.exit(0)
        else:
            sys.exit(1)
