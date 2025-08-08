import os
import argparse
import logging

from pathlib import Path
import sys

from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "building", "oss_fuzz.build.image")
tracer = get_otel_tracer()
log = logging.getLogger("oss-fuzz-build-image")


def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description="Build instrumented projects")
    parser.add_argument(
        "target_path", type=Path, help="Path to the oss-fuzz project directory"
    )
    parser.add_argument(
        "--full-build-with-prebuild-image",
        action="store_true",
        help="Build the target project with the prebuilt image. This is only available outside of the pipeline environment to ensure our pipeline builds remain fast.",
    )
    # parser.add_argument('--rebuild-base-image', action='store_true', help='Rebuild the target base image')
    parser.add_argument(
        "--build-runner-image",
        action="store_true",
        help="Build the runner image instead of the builder image",
    )
    parser.add_argument(
        "--push", action="store_true", help="Push the image to the registry"
    )
    parser.add_argument(
        "--instrumentation",
        type=str,
        help="Instrumentation to apply",
        choices=SUPPORTED_INSTRUMENTATIONS.keys(),
        required=True,
    )
    parser.add_argument(
        "--secret",
        type=str,
        help="Secret to use for the build",
        required=False,
        default=None,
    )
    args = parser.parse_args()

    with tracer.start_as_current_span("oss_fuzz_build_image") as span:

        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]

        instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            args.target_path,
        )

        if args.secret:
            instr_project.set_secret(args.secret)

        if args.full_build_with_prebuild_image:
            assert not os.environ.get("IN_K8S", ''), "This option is not available in the full pipeline environment. This should have been run ahead of time"
            instr_project.build_prebuild_image(push=args.push)

        if args.build_runner_image:
            image_name = instr_project.build_runner_image(push=args.push)
        else:
            image_name = instr_project.build_builder_image(push=args.push)

    # DO NOT REMOVE OR ALTER THIS PRINT. THE LIFE OF THE PIPELINE DEPENDS ON IT.
    # ESPECIALLY, DO NOT EVER REPLACE IT WITH LOGGING.
    print("IMAGE_NAME: {}".format(image_name))
    print("IMAGE_NAME(stderr): {}".format(image_name), file=sys.stderr)
