import argparse
from collections import defaultdict
import os
import glob
from pathlib import Path
import sys

from shellphish_crs_utils.models.oss_fuzz import ArchitectureEnum, SanitizerEnum
from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "building", "oss_fuzz.build")
tracer = get_otel_tracer()

def parse_volume(volume: str) -> tuple[str, str]:
    """
    Parse a volume string in the format "host_path:container_path".
    """
    parts = volume.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid volume format: {volume}. Expected 'host_path:container_path'.")
    return parts[0], parts[1]
def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description='Build instrumented projects')
    parser.add_argument('target_path', type=Path, help='Path to the oss-fuzz project directory')
    parser.add_argument(
        "--full-build-with-prebuild-image",
        action="store_true",
        help="Build the target project with the prebuilt image. This is only available outside of the pipeline environment to ensure our pipeline builds remain fast.",
    )
    parser.add_argument('--architecture', type=str, help='Architecture to build for', choices=[v.value for v in ArchitectureEnum], default=ArchitectureEnum.x86_64.value)
    parser.add_argument('--use-task-service', action='store_true', help='Use the pipeline task service to build the project')
    parser.add_argument('--project-id', type=str, help='Project ID to use for the build', required=False, default=None)
    parser.add_argument('--no-rebuild-docker-images', action='store_true', help='Do not rebuild the build docker image')
    parser.add_argument('--no-clean-target', action='store_true', help='Do not recreate the target directories before building')
    parser.add_argument('--sanitizer', type=str, help='Sanitizer to apply', choices=[v.value for v in SanitizerEnum], required=True)
    parser.add_argument('--instrumentation', type=str, help='Instrumentation to apply', choices=SUPPORTED_INSTRUMENTATIONS.keys(), required=True)
    parser.add_argument('--extra-env', type=str, help='Extra environment variables to set', action='append', default=[])
    parser.add_argument('--extra-file', type=str, help='Extra files to copy to the container (src:dst)', action='append', default=[])
    parser.add_argument('--no-cache', action='store_true', help='Do not use docker cache when building')
    parser.add_argument('--no-compiler-cache', action='store_true', help='Do not use ccache when building.')
    parser.add_argument('--secret', type=str, help='Secret to use for the build', required=False, default=None)
    parser.add_argument('--patch-path', type=Path, help='Path to the patch to apply', required=False, default=None)
    parser.add_argument('--priority', type=float, help='Priority of the build', required=False, default=2.0)
    parser.add_argument('--cpu', type=int, help='CPUs for the container', required=False, default=None)
    parser.add_argument('--mem', type=str, help='Memory for the container (e.g. 40Gi)', required=False, default=None)
    parser.add_argument('--max-cpu', type=int, help='Maximum CPU to use for the build before OOMKilling', required=False, default=None)
    parser.add_argument('--max-mem', type=str, help='Maximum memory to use for the build (e.g. 40Gi)', required=False, default=None)
    parser.add_argument('--max-resources', type=float, help='Maximum resources to use for the build (as a percentage of total resources)', required=False, default=None)
    parser.add_argument('--project-source', type=Path, help='Path to the project source', required=False, default=None)
    parser.add_argument("--preserve-built-src-dir", action="store_true", help="Preserve the built source directory in artifacts/out/src/")
    parser.add_argument("--git-ref", type=str, help="Git reference to checkout before building", required=False, default=None)
    parser.add_argument("--DANGER-only-for-debugging-volume", type=parse_volume, default=None, help="Mount the volumes in the docker container for debugging purposes. This should NEVER be used in production. It will mount the volumes in the container and will not remove them after the build. This is only for debugging purposes.")
    args = parser.parse_args()
    with tracer.start_as_current_span("oss_fuzz_build") as span:

        assert args.architecture == ArchitectureEnum.x86_64.value, """
    Only x86_64 is supported for now. If you add support for others you have to add it to the actual implementation.
    It's currently entirely unsupported and unimplemented.
    """

        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]
        extra_env = {}
        for extra_env_key, extra_env_val in os.environ.items():
            if extra_env_key.startswith('ARTIPHISHELL_OSSFUZZ_BUILD_EXTRA_ENV_'):
                extra_env[extra_env_key[len('ARTIPHISHELL_OSSFUZZ_BUILD_EXTRA_ENV_'):]] = extra_env_val

        for env in args.extra_env:
            key, value = env.split('=', maxsplit=1)
            extra_env[key] = value

        extra_files = {}
        for file in args.extra_file:
            src, dst = file.split(':', maxsplit=1)
            extra_files[src] = dst

        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            args.target_path,
            project_source=args.project_source,
            use_task_service=args.use_task_service,
            project_id=args.project_id,
        )

        if args.secret:
            instr_project.set_docker_build_secret(args.secret)
        if args.no_cache:
            instr_project.no_cache()
         
        if args.no_compiler_cache or args.instrumentation == "shellphish_codeql" or dict(os.environ).get('ARTIPHISHELL_CCACHE_DISABLE', '') == '1':
            instr_project.no_compiler_cache()
        else:
            print("Using ccache for compilation. Set --no-compiler-cache to disable this.")

        # import ipdb; ipdb.set_trace()
        if not args.no_rebuild_docker_images:
            if args.full_build_with_prebuild_image:
                assert not os.environ.get("IN_K8S", ''), "This option is not available in the full pipeline environment. This should have been run ahead of time"
                instr_project.build_prebuild_image()
            instr_project.build_builder_image()

        if not args.no_clean_target:
            instr_project.reset_artifacts_dirs()
       
        quota = {}
        if args.cpu or args.mem:
            quota = {
                'cpu' : f"{args.cpu if args.cpu else 6}",
                'mem' : args.mem if args.mem else '26Gi',
            }
        elif args.max_resources:
            quota = {
                'max' : args.max_resources,
            }
        else:
            # TODO(FINALDEPLOY) increase to 10/40Gi
            quota = {
                'cpu': '10',
                'mem': '40Gi',
            }
            
        resource_limits = {
            'cpu': f"{args.max_cpu if args.max_cpu else 10}",
            'mem': args.max_mem if args.max_mem else '40Gi',
        }

        if 'cpu' in quota:
            if int(quota['cpu']) > int(resource_limits['cpu']):
                print(f"Warning: Quota CPU ({quota['cpu']}) is greater than resource limits CPU ({resource_limits['cpu']}). This may lead to OOMKills or pod not starting.")
            if int(quota['mem'].replace('Gi', '')) > int(resource_limits['mem'].replace('Gi', '')):
                print(f"Warning: Quota memory ({quota['mem']}) is greater than resource limits memory ({resource_limits['mem']}). This may lead to OOMKills or pod not starting.")
        
        print(repr(args.DANGER_only_for_debugging_volume))
        result = instr_project.build_target(
            sanitizer=args.sanitizer,
            extra_env=extra_env,
            extra_files=extra_files,
            patch_path=args.patch_path,
            preserve_built_src_dir=args.preserve_built_src_dir,
            git_ref=args.git_ref,
            priority=args.priority,
            quota=quota,
            resource_limits=resource_limits,
        )

        print(f"Task Success: {result.task_success}")
        print(f"Run Exit Code: {result.run_exit_code}")
        print(f"Time Scheduled: {result.time_scheduled}")
        print(f"Time Started: {result.time_start}")
        print(f"Time Ended: {result.time_end}")
        print(f"Time Taken: {result.time_taken}")
        try:
            print(f"Stdout: {result.stdout.decode('latin-1')}")
        except Exception as e:
            try:
                out_str = b"Stdout: " + result.stdout
                sys.stdout.buffer.write(out_str)
            except Exception as e:
                print("Stdout: ", result.stdout)
            
        try:
            print(f"Stderr: {result.stderr.decode('latin-1')}")
        except Exception as e:
            try:
                out_str = b"Stderr: " + result.stderr
                sys.stdout.buffer.write(out_str)
            except Exception as e:
                print("Stderr: ", result.stderr)
    
        print(f"Container ID: {result.container_id}")
        print(f"Container Name: {result.container_name}")
        print(f"Build Job PDT ID: {result.build_job_pdt_id}")
        print(f"Build Request ID: {result.build_request_id}")
        print(f"Build Success: {result.build_success}")
        print(f"Out Dir: {result.out_dir}")

        print(f"Build task      {'succeeded' if result.task_success else 'failed'}!")
        print(f"Target build    {'succeeded' if result.build_success else 'failed'}!")
        print(f"Output directory: {result.out_dir}")
        if result.out_dir:
            print(f"stdout log: ", result.out_dir / 'stdout.log')
            print(f"stderr log: ", result.out_dir / 'stderr.log')
        else:
            print(f"stdout log: ", None)
            print(f"stderr log: ", None)
        
        if result.task_success and result.build_success:
            sys.exit(0)
        else:
            sys.exit(1)
