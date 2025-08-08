import argparse
import logging
import os
import sys
from pathlib import Path

import patchery
from patchery import Patcher
from patchery.ranker import PatchRanker
from patchery.deduplicator import PatchDeduplicator
from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel, get_current_span, status_error

init_otel("patchery", "patch_generation", "llm_patch_generation")
init_llm_otel()
tracer = get_otel_tracer()

INFO_ONLY=os.getenv("INFO_ONLY", False)

_l = logging.getLogger("patchery")
kumushi_logger = logging.getLogger("kumushi")

if not INFO_ONLY:
    _l.setLevel(logging.DEBUG)
else:
    _l.setLevel(logging.INFO)
    kumushi_logger.setLevel(logging.INFO)

@tracer.start_as_current_span("patchery.main")
def main():
    """
    Does the parsing of arguments and calls out to different sections of PatcherY responsible for different tasks.
    Take note of the special mode:
    --generate-aixcc-patch

    Which is used only in the AIxCC competition. This will include dynamic imports.
    """

    parser = argparse.ArgumentParser(
        description="""
        The PatcherY CLI, useful for patching based on TOML reports.
        """,
        epilog="""
        Examples:
        patchery --version
        """,
    )
    parser.add_argument("--version", "-v", action="version", version=patchery.__version__)

    #
    # Mode Selection
    #

    parser.add_argument(
        "--deduplicate-patches",
        type=Path,
        help="""
        Deduplicate patches in the given directory.
        """,
    )

    parser.add_argument(
        "--rank-patches",
        type=Path,
        help="""
        Ranks the patches in the given directory. Uses --rank-output-file to save the results.
        """,
    )

    parser.add_argument(
        "--generate-aixcc-patch",
        action="store_true",
        help="""
        Generate verified patches. Requires the following arguments:
        --src-root, --poi-file, --poi-func, --poi-line, --run-script, --report-file, --raw-report
        """,
    )
    
    parser.add_argument(
        "--local-run",
        action="store_true",
        default=False,
        help="""
        Whether run the patching process locally.
        """,
    )

    #
    # AIxCC Patch Generation
    #

    parser.add_argument(
        "--report-yaml",
        type=Path,
        help="""
        """,
    )
    parser.add_argument(
        "--target-root",
        type=Path,
        help="The root directory of the oss-fuzz target.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help="The root directory of the source in which the patches will be applied.",
    )
    parser.add_argument(
        '--project-metadata',
        type=Path,
        help="The path to the yaml saving the patch metadata, from which we can get the source_root",
    )
    parser.add_argument(
        "--function-json-dir",
        type=Path,
        help="Path to the directory that contain all functions/classes/methods of the target",
    )
    parser.add_argument(
        "--functions-by-commit-jsons-dir",
        type=Path,
        help="Path to the directory that contain the functions/classes/methods of the target for each commit",
    )
    parser.add_argument(
        "--function-indices",
        type=Path,
        help="Path to the json file with info on the PoI function/method",
    )
    parser.add_argument(
        "--indices-by-commit", type=Path, help="Path to the indices of changed functions for each commit"
    )
    parser.add_argument(
        "--coverage-build-artifacts-path", type=Path,
        help="Path to the directory that contains the coverage build artifacts",
    )
    #
    # Execution (verification) Information
    #

    parser.add_argument(
        "--benign-inputs",
        type=Path,
        help="The path to the benign inputs.",
    )
    parser.add_argument(
        "--alerting-inputs",
        type=Path,
        help="The path to the alerting inputs.",
    )

    #
    # Ranking flags
    #

    parser.add_argument(
        "--rank-patch-verifications",
        type=Path,
        help="""
        Directory of files containing amount of times a patch crashed on other inputs.
        """,
    )
    parser.add_argument(
        "--rank-patch-metadatas",
        type=Path,
        help="""
        Metadata of the patches to rank.
        """,
    )
    parser.add_argument(
        "--rank-output-dir",
        type=Path,
        help="""
        The directory to save the ranked patches. Should be used with --rank-patches. Each rank file will be named
        `patch_rank_<timestamp>.json`, where the timestamp is the time the rank was generated. We deciding the best
        patch based on the ranking, always use the latest rank file.
        """,
    )
    parser.add_argument(
        "--continuous-ranking",
        action="store_true",
        default=False,
        help="""
        If set, the patcher will continuously rank patches in the directory until a timeout is reached.
        """,
    )
    parser.add_argument(
        "--rank-timeout",
        type=int,
        help="""
        The time in seconds to rank patches. Only used with --continuous-ranking.
        """,
    )
    parser.add_argument(
        "--rank-wait-time",
        type=int,
        help="""
        The time in seconds to wait between ranking patches. Only used with --continuous-ranking.
        """,
    )

    #
    # Kumushi Report
    #
    parser.add_argument("--kumushi-report", help="The path to the Kumushi report.")

    #
    # Optional args for targets
    #

    parser.add_argument(
        "--c-reproducer-folder",
        help="The path to the folder containing the C reproducer files.",
    )
    parser.add_argument(
        "--kernel-image-dir",
        help="The path of the kernel bzImage file.",
    )
    parser.add_argument(
        "--patch-output-dir",
        type=Path,
        help="The path to save the verified patch.",
    )
    parser.add_argument("--patch-meta-output-dir", type=Path, help="The path to save the patch metadata")
    parser.add_argument(
        "--raw-report",
        type=Path,
        help="The path to the raw report file.",
    )
    parser.add_argument(
        "--crashing-commit",
        help="The commit that caused the crash.",
    )
    parser.add_argument(
        "--invariance-report",
        type=Path,
        help="The path to the invariance report.",
    )
    parser.add_argument(
        "--debug-report",
        type=Path,
        help="The path to the debug report.",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        help="Number of attempts for one poi.",
    )
    parser.add_argument(
        "--max-pois",
        type=int,
        help="Number of pois to patch.",
    )

    parser.add_argument(
        "--patch-planning",
        action="store_true",
        help="Plan the patching process."
    )

    parser.add_argument(
        "--patch-requests-meta",
        type=Path,
        help="The path to the patch request metadata file.",
    )

    parser.add_argument(
        "--bypassing-inputs",
        type=str,
        help="The bypassing inputs from fuzz pass"
    )
    #
    # Patch Request Metadata
    #

    args = parser.parse_args()
    # TODO: add ability to patch non-aixcc projects
    make_patches = args.generate_aixcc_patch
    if make_patches:
        #
        # Patch Generation
        #

        patcher: Patcher = None
        if args.generate_aixcc_patch:
            with tracer.start_as_current_span("aixcc_patcher") as span:
                from patchery.aicc_patcher import AICCPatcher
                patcher = AICCPatcher.from_files(
                    target_root=args.target_root,
                    source_root=args.source_root,
                    report_yaml_path=args.report_yaml,
                    project_metadata_path=args.project_metadata,
                    raw_report_path=args.raw_report,
                    function_json_dir=args.function_json_dir,
                    function_indices=args.function_indices,
                    alerting_inputs_path=args.alerting_inputs,
                    benign_inputs_path=args.benign_inputs,
                    patch_output_dir=args.patch_output_dir,
                    patch_metadata_output_dir=args.patch_meta_output_dir,
                    c_reproducer_folder=args.c_reproducer_folder,
                    kernel_image_dir=args.kernel_image_dir,
                    invariance_report=args.invariance_report,
                    crashing_commit=args.crashing_commit,
                    indices_by_commit=args.indices_by_commit,
                    changed_func_by_commit=args.functions_by_commit_jsons_dir,
                    debug_report=args.debug_report,
                    max_attempts=args.max_attempts,
                    max_pois=args.max_pois,
                    patch_planning=args.patch_planning,
                    local_run=args.local_run,
                    kumushi_report_path=args.kumushi_report,
                    coverage_build_project_path=args.coverage_build_artifacts_path,
                    patch_request_meta=args.patch_requests_meta,
                    bypassing_inputs=args.bypassing_inputs,
                    should_init_resolver=True,
                )

        if not isinstance(patcher, Patcher):
            raise ValueError("No patcher was created. Exiting.")
        patches = patcher.generate_verified_patches()
        if patches:
            sys.exit(0)
        else:
            sys.exit(1)
                
    elif args.rank_patches:
        #
        # Patch Ranking
        #

        if not args.rank_patches.exists():
            raise FileNotFoundError(f"Patch directory '{args.rank_patches}' does not exist")

        PatchRanker.rank_many_aicc_patch_dirs(
            patches_dir=args.rank_patches,
            previous_crashes_dir=args.rank_patch_verifications,
            patch_metadatas_dir=args.rank_patch_metadatas,
            continuous=args.continuous_ranking,
            rank_output_dir=args.rank_output_dir,
            wait_time=args.rank_wait_time,
            timeout=args.rank_timeout,
        )
    elif args.deduplicate_patches:
        #
        # Patch Deduplication
        #

        if not args.deduplicate_patches.exists():
            raise FileNotFoundError(f"Patch directory '{args.deduplicate_patches}' does not exist")

        PatchDeduplicator.dedupe_many_aicc_patch_dirs(
            args.deduplicate_patches,
            patch_metadata_dir=args.rank_patch_metadatas,
        )
    else:
        args.display_help()


#
# Main runner
#

if __name__ == "__main__":
    main()
