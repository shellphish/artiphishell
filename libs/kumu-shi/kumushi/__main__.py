import argparse
import kumushi
import logging
import yaml
from pathlib import Path

from kumushi.root_cause_analyzer import RootCauseAnalyzer
from kumushi.rca_mode import RCAMode
from kumushi.aixcc import AICCProgram
from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
)
from shellphish_crs_utils.models.crs_reports import PatchRequestMeta

init_otel("kumushi", "dynamic_analysis", "root_cause_analysis")
tracer = get_otel_tracer()


_l = logging.getLogger(__name__)


PATHABLE_ARGS = (
    "report_yaml",
    "source_root",
    "function_json_dir",
    "functions_by_commit_jsons_dir",
    "function_indices",
    "indices_by_commit",
    "crash_input",
    "coverage_target_dir",
    "coverage_target_metadata_path",
    "coverage_build_project_path",
    "aflpp_build_project_path",
)


def main():
    parser = argparse.ArgumentParser(
        description="KumuShi: A tool for root-cause analysis of crashes"
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{kumushi.__version__}",
        default=False,
    )
    parser.add_argument(
        "--report-yaml",
        help="""
        """,
    )
    parser.add_argument(
        "--source-root",
        help="The root directory of the target in which the patches will be applied.",
        required=True,
    )
    parser.add_argument("--crash-input", type=Path, required=True)
    parser.add_argument(
        "--target-root",
        help="The root directory of the oss-fuzz target.",
    )
    parser.add_argument(
        "--local-run",
        action="store_true",
        default=False,
        help="""
        Whether run the process locally.
        """,
    )
    parser.add_argument("--project-metadata")
    #
    # Clang Cache Information
    #

    parser.add_argument(
        "--function-json-dir",
        help="Path to the directory that contain all functions/classes/methods of the target",
    )
    parser.add_argument(
        "--functions-by-commit-jsons-dir",
        help="Path to the directory that contain the functions/classes/methods of the target for each commit",
    )
    parser.add_argument(
        "--function-indices",
        help="Path to the json file with info on the PoI function/method",
    )
    parser.add_argument(
        "--indices-by-commit",
        help="Path to the indices of changed functions for each commit",
    )

    #
    # SmartCallTracer
    #

    parser.add_argument("--coverage-target-dir")
    parser.add_argument("--coverage-target-metadata-path")
    parser.add_argument("--debug-build-project-path")

    #
    # Aurora
    #

    parser.add_argument("--coverage-build-project-path", help="Path to coverage build artifact, e.g., /aixcc-backups/backup-nginx-14747039175/coverage_build_c.coverage_build_artifacts/24208a4c85184f96b56b8f239ec21d2e")
    parser.add_argument("--crashing-input-dir", type=str, help="a dir containing crashing inputs, triggering the same crash as the one in --crash-input, but cover different code paths", default=None)

    #
    # Diffguy
    #
    parser.add_argument("--diffguy-reports", type=str)

    #
    # DYVA
    #
    parser.add_argument("--dyva-report-path", type=str)

    #
    # RCA Mode
    #

    parser.add_argument("--light-mode", action="store_true", help="Run in light mode")
    parser.add_argument("--heavy-mode", action="store_true", help="Run in heavy mode")
    parser.add_argument("--hybrid-mode", action="store_true", help="Run in hybrid mode")

    parser.add_argument(
        "--light-output-dir", help="Output directory for light analysis"
    )
    parser.add_argument(
        "--output-dir", help="Output directory for heavy analysis"
    )

    #
    # AIXCC Mode
    #

    parser.add_argument('--aixcc', action='store_true', help="Run in AIXCC mode")
    parser.add_argument('--delta-mode', action='store_true', help="Run in delta mode")
    parser.add_argument('--full-mode', action='store_true', help="Run in full mode")
    parser.add_argument('--java-mode', action='store_true', help="Run with Java targets")
    parser.add_argument('--patch-request-meta', help="Path to the patch metadata request file")
    args = parser.parse_args()

    # version check
    if args.version:
        print(f"{kumushi.__version__}")
        return

    if args.aixcc:
        if args.hybrid_mode:
            rca_mode = RCAMode.HYBRID
        elif args.light_mode:
            rca_mode = RCAMode.LIGHT
        elif args.heavy_mode:
            rca_mode = RCAMode.HEAVY

        aflpp_build_project_path = None

        crashing_input_dir = None
        if args.crashing_input_dir:
            crashing_input_dir = Path(args.crashing_input_dir)

        diffguy_report_path = None
        if args.diffguy_reports:
            diffguy_reports = list(Path(args.diffguy_reports).rglob("*.json"))
            for report in diffguy_reports:
                if report.name == "diffguy_report.json":
                    diffguy_report_path = report

        aicc_program = AICCProgram.from_files(
            Path(args.source_root),
            Path(args.target_root),
            Path(args.project_metadata),
            Path(args.report_yaml),
            Path(args.function_indices) if args.function_indices else None,
            Path(args.function_json_dir) if args.function_json_dir else None,
            indices_by_commit=Path(args.indices_by_commit) if args.indices_by_commit else None,
            functions_by_commit_jsons_dir=Path(args.functions_by_commit_jsons_dir) if args.functions_by_commit_jsons_dir else None,
            delta_mode=args.delta_mode,
            crashing_input_paths=[Path(args.crash_input)] if args.crash_input else [],
            coverage_build_project_path=args.coverage_build_project_path,
            aflpp_build_project_path=aflpp_build_project_path,
            local_run=args.local_run, diffguy_report_path=diffguy_report_path,
            crashing_input_dir=crashing_input_dir,
            coverage_target_dir=args.coverage_target_dir, patch_request_meta=args.patch_request_meta,
            debug_build_project_path=args.debug_build_project_path, dyva_report_path=args.dyva_report_path
        )

        # if 'refine' == aicc_program.patch_request_metadata.request_type:
        #     rca_mode = RCAMode.WEIGHTLESS

        rca = RootCauseAnalyzer(
            aicc_program,
            rca_mode=rca_mode,
            output_folder=args.output_dir,
            is_java=args.java_mode,
        )
        rca.analyze()


if __name__ == "__main__":
    with tracer.start_as_current_span("kumushi") as span:
        main()
        span.set_status(status_ok())
