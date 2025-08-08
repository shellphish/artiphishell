import os
import argparse
import logging

from pathlib import Path

from shellphish_crs_utils.oss_fuzz.instrumentation import SUPPORTED_INSTRUMENTATIONS
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "building", "oss_fuzz.build.image")
tracer = get_otel_tracer()
log = logging.getLogger("oss-fuzz-build-image")

CUR_DIR = Path(__file__).parent
DEMO_OSS_FUZZ_TARGETS_DIR = CUR_DIR / "demo-oss-fuzz-targets"

def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    # import ipdb; ipdb.post_mortem()
    parser = argparse.ArgumentParser(description="Build instrumented projects")
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

    with tracer.start_as_current_span("oss_fuzz_prebuild_instrumentation_image") as span:

        instrumentation = SUPPORTED_INSTRUMENTATIONS[args.instrumentation]

        instr_project_c = InstrumentedOssFuzzProject(
            instrumentation,
            DEMO_OSS_FUZZ_TARGETS_DIR / 'c',
        )
        instr_project_java = InstrumentedOssFuzzProject(
            instrumentation,
            DEMO_OSS_FUZZ_TARGETS_DIR / 'java',
        )
        instr_projects = [instr_project_c, instr_project_java]

        for proj in instr_projects:
            if args.secret:
                proj.set_secret(args.secret)

            assert not os.environ.get("IN_K8S", ''), "This option is not available in the full pipeline environment. This should have been run ahead of time"
            prebuild_image = proj.build_prebuild_image(push=args.push)

            # image_name_builder = proj.build_runner_image(push=args.push)
            # image_name_runner = proj.build_builder_image(push=args.push)

            # DO NOT REMOVE OR ALTER THIS PRINT. THE LIFE OF THE PIPELINE DEPENDS ON IT.
            # ESPECIALLY, DO NOT EVER REPLACE IT WITH LOGGING.
            print("IMAGE_NAME: {}".format(prebuild_image))
            # print("IMAGE_NAME: {}".format(image_name_builder))
            # print("IMAGE_NAME: {}".format(image_name_runner))
