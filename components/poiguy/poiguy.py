#!/usr/bin/env python3

import argparse
import logging
from typing import Dict, List, Optional
from shellphish_crs_utils.function_resolver import FunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.crash_reports import CallTraceEntry
from shellphish_crs_utils.models.crs_reports import POIReport, PoVReport
from shellphish_crs_utils.models.indexer import ReducedFunctionIndex, FunctionsByFile
from shellphish_crs_utils.models.symbols import POI, JavaInfo, SourceLocation, RelativePathKind
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum, SanitizerEnum, ArchitectureEnum
from shellphish_crs_utils.models.organizer_evaluation import OrganizerCrashEvaluation, SignificanceEnum
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
    status_error,
)
import yaml
import json
import traceback

from pathlib import Path

init_otel("poiguy", "static_analysis", "crash_report_parsing")
tracer = get_otel_tracer()

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]")

log = logging.getLogger("POIGuy")

def produce_poi_report(
    project_id: str,
    report_id: str,
    report: Path,
    project_metadata_path: Path,
) -> POIReport:
    with report.open("r") as f:
        data = yaml.safe_load(f)
        pov_crash_report = PoVReport.model_validate(data)
        dedup_crash_report = pov_crash_report.dedup_crash_report

    assert dedup_crash_report is not None, "Dedup crash report is None"
    with project_metadata_path.open("r") as f:
        project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

    processed_pois: List[POI] = []
    harness_name = pov_crash_report.cp_harness_name

    try:
        function_resolver = RemoteFunctionResolver(
            cp_name=pov_crash_report.project_name,
            project_id=project_id,
        )
    except Exception as e:
        log.error("Error initializing function resolver: %s", e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise
        function_resolver = None

    for stack_trace_name, stack_trace in dedup_crash_report.stack_traces.items():
        for cte in stack_trace.call_locations:
            if function_resolver is not None:
                try:
                    cte.enhance_with_function_resolver(function_resolver) # try it again, just to be safe.
                except Exception as e:
                    log.error("Error enhancing CTE at %s", cte, exc_info=True)
            try:
                if (
                    cte.source_location
                    and cte.source_location.function_index_key
                    and cte.source_location.full_file_path
                    and cte.source_location.full_file_path.stem != harness_name
                ):
                    poi = POI(
                        reason=dedup_crash_report.crash_type,
                        source_location=cte.source_location,
                    )
                    processed_pois.append(poi)
                    log.info("Processed POI: %s", poi)
            except Exception as e:
                log.error("Error processing POI at %s", cte, exc_info=True)
                log.error("Error: %s", e)
                if artiphishell_should_fail_on_error():
                    raise

    reduced_report = dedup_crash_report.model_dump()
    reduced_report.pop("stack_traces")
    reduced_report.pop("sanitizer")
    reduced_report.pop("crash_type")

    poi = POIReport(
        # harness_info
        build_configuration_id=pov_crash_report.build_configuration_id,
        project_harness_metadata_id=pov_crash_report.project_harness_metadata_id,
        project_id=pov_crash_report.project_id,
        project_name=pov_crash_report.project_name,
        cp_harness_name=pov_crash_report.cp_harness_name,
        cp_harness_binary_path=pov_crash_report.cp_harness_binary_path,
        architecture=pov_crash_report.architecture,
        sanitizer=pov_crash_report.sanitizer,
        # POIReport
        harness_info_id=pov_crash_report.harness_info_id,
        detection_strategy="fuzzing",
        fuzzer=pov_crash_report.fuzzer,
        organizer_crash_eval=pov_crash_report.organizer_crash_eval,
        # sanitizer_history=pov_crash_report.sanitizer_history,
        crash_report_id=report_id,
        crash_reason=dedup_crash_report.crash_type,
        consistent_sanitizers=pov_crash_report.consistent_sanitizers,
        inconsistent_sanitizers=pov_crash_report.inconsistent_sanitizers,
        # **reduced_report,
        pois=processed_pois,
        stack_traces=dedup_crash_report.stack_traces,
        extra_context=pov_crash_report.extra_context,
        additional_information={
            "asan_report_data": json.loads(dedup_crash_report.model_dump_json()),
            "sanitizer": dedup_crash_report.sanitizer,
        },
    )
    return poi

def generate_dirty_poi_report(
    project_id: str,
    report_id: str,
    report: Path,
    project_metadata_path: Path,
) -> POIReport:
    """
    In case of error, we generate a dirty POI report with as much information as possible.
    This is to ensure that the pipeline can still progress.
    """
    try:
        with report.open("r") as f:
            data = yaml.safe_load(f)
            pov_report = PoVReport.model_validate(data)
    except Exception as e:
        log.error("Error parsing POV report: %s", e, exc_info=True)
        pov_report = None
    
    try:
        with project_metadata_path.open("r") as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
    except Exception as e:
        log.error("Error parsing project metadata: %s", e, exc_info=True)
        project_metadata = None
    
    if project_metadata is None:
        project_metadata = AugmentedProjectMetadata(
            language=LanguageEnum.c,
            labels={},
        )
    
    if pov_report is None:
        pov_report = PoVReport(
            consistent_sanitizers=["ERROR"],
            inconsistent_sanitizers=[],
            harness_info_id="ERROR",
            fuzzer="ERROR",
            build_configuration_id="ERROR",
            project_id=project_id,
            project_name="ERROR",
            sanitizer=SanitizerEnum.address,
            architecture=ArchitectureEnum.x86_64,
            cp_harness_name="ERROR",
            cp_harness_binary_path=Path("/dev/null"),
            parser="failed",
            exception="Failed to parse POV report",
            triggered_sanitizers=["ERROR"],
            organizer_crash_eval=OrganizerCrashEvaluation(
                code_label="ERROR",
                significance=SignificanceEnum.NoSignificantCrashRecognized,
                significance_message="No significant crash recognized",
                crash_state="ERROR",
                instrumentation_key="ERROR",
            ),
        )
    pois = []
    if pov_report.dedup_crash_report is not None and pov_report.dedup_crash_report.stack_traces:
        for stack_trace_name, stack_trace in pov_report.dedup_crash_report.stack_traces.items():
            for cte in stack_trace.call_locations:
                if cte.source_location:
                    poi = POI(
                        source_location=cte.source_location,
                    )
                    pois.append(poi)
    # if not pois:
    #     pois = [POI(
    #         reason="Failed to parse POV report",
    #         source_location=SourceLocation(
    #             full_file_path=Path("/dev/null"),
    #             relative_path=Path("/dev/null"),
    #             file_name=Path("null"),
    #             function_name="ERROR",
    #             line_number=0,
    #             line_text="ERROR",
    #             symbol_offset=0,
    #             symbol_size=0,
    #         ),
    #     )]
    
    for poi in pois:
        if poi.source_location is None:
            continue
        if poi.source_location.focus_repo_relative_path is not None:
            break
    else:
        # There is no repo relative path, so we die.
        raise ValueError("All POIs are non-repo relative paths, this is not expected")
    assert len(pois) > 0, "No POIs found in POV report, this is unexpected"
    

    poi_report = POIReport(
        harness_info_id=pov_report.harness_info_id,
        organizer_crash_eval=pov_report.organizer_crash_eval,
        build_configuration_id=pov_report.build_configuration_id,
        detection_strategy="fuzzing",
        fuzzer=pov_report.fuzzer,
        consistent_sanitizers=pov_report.consistent_sanitizers,
        inconsistent_sanitizers=pov_report.inconsistent_sanitizers,
        crash_report_id=report_id,
        cp_harness_name=pov_report.cp_harness_name,
        cp_harness_binary_path=pov_report.cp_harness_binary_path,
        project_id=project_id,
        project_name=pov_report.project_name,
        architecture=pov_report.architecture,
        sanitizer=pov_report.sanitizer,
        crash_reason="ERROR",
        pois=pois,
        stack_traces={},
    )
    return poi_report


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-id", type=str, required=True)
    parser.add_argument("--harness-info-id", type=str, required=False)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--report-id", type=str, required=False, default=None)
    parser.add_argument("--project-metadata", type=Path, required=False, default=None)
    parser.add_argument("--output", type=Path, required=True)

    return parser.parse_args()


if __name__ == "__main__":
    with tracer.start_as_current_span("poiguy") as span:
        args = get_args()

        try:
            poi_report = produce_poi_report(
                args.project_id,
                args.report_id,
                args.report,
                args.project_metadata,
            )
            with args.output.open("w") as f:
                f.write(poi_report.model_dump_json(indent=2))
            span.add_event(
                "poiguy.poi_report", {"poi_report": poi_report.model_dump_json()}
            )
            span.set_status(status_ok())

        except Exception as e:
            logging.error(f"Error: {e}", exc_info=True)
            traceback.print_exc()
            if artiphishell_should_fail_on_error():
                raise

            try:
                logging.info("Attempting to generate dirty POI report...")
                poi_report = generate_dirty_poi_report(
                    args.project_id,
                    args.report_id,
                    args.report,
                    args.project_metadata,
                )
                logging.info("Dirty POI report generated successfully!")
                with args.output.open("w") as f:
                    f.write(poi_report.model_dump_json(indent=2))
            except Exception as e:
                if artiphishell_should_fail_on_error():
                    raise
                logging.error("We failed to generate a dirty POI report, but we will try to continue.", exc_info=True)
                # with args.output.open("w") as f:
                #     f.write(json.dumps({"project_id": args.project_id, "report_id": args.report_id, "harness_info_id": None}, indent=2))
                exit(1)
            # poiguy has failure_ok set so we should raise the exception to fail the task regardless to ensure it's visible.
            # this will not stop the pipeline. however, if fail_early is set it will not output the report and therefore
            # the pipeline will not progress.
            span.set_status(status_error(), "Error parsing crash report")
