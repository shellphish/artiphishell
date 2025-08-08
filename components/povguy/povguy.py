import hashlib
import shutil
from analysis_graph.models.harness_inputs import HarnessInputNode
from shellphish_crs_utils.function_resolver import FunctionResolver, List, RemoteFunctionResolver
from shellphish_crs_utils.models.crash_reports import CallTraceEntry
from shellphish_crs_utils.models.organizer_evaluation import SignificanceEnum
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
import yaml
import time
import argparse
import subprocess
import os
import stat
import tempfile
import logging
import json

from pathlib import Path
from typing import Optional


from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject, InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.jazzer import JazzerInstrumentation
from shellphish_crs_utils.models import (
    DedupPoVReportRepresentativeMetadata,
    RunPoVResult,
    RepresentativeFullPoVReport,
    PoVReport,
    CrashingInputMetadata,
)
from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
    init_llm_otel,
    get_current_span,
    status_error,
)
from analysis_graph.models import crashes as analysis_graph_crash_reports

init_otel("povguy", "testing", "pov_validation")
init_llm_otel()
telemetry_tracer = get_otel_tracer()

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]")

log = logging.getLogger("povguy")
#log.propagate = False


def calculate_md5(file_path: Path) -> str:
    hash_md5 = hashlib.md5()
    if file_path.exists():
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    return f"File {file_path} does not exist"

def run_pov(
    base_meta_path: Path,
    out_per_crash_full_pov_report_path: Path,
    out_dedup_pov_report_path: Path,
    out_dedup_pov_report_representative_metadata_path: Path,
    out_dedup_pov_report_representative_crash_path: Path,
    out_dedup_pov_report_representative_full_report_path: Path,
    out_dedup_losan_report_path: Path,
    out_dedup_losan_report_representative_metadata_path: Path,
    out_dedup_losan_report_representative_crash_path: Path,
    out_dedup_losan_report_representative_full_report_path: Path,
    project_dir: Path,
    harness_name: str,
    pov_path: Path,
    crash_id: str,
    expect_crashing=True,
    timeout=None,
    retry_count=5,
    base_project: Optional[Path] = None,
):
    log.info("Running pov %s with harness %s", pov_path, harness_name)
    with open(base_meta_path, "r") as f:
        base_meta = yaml.safe_load(f)
    if "project_name" in base_meta:
        base_meta["project_name"] = str(base_meta["project_name"])
    crash_metadata = CrashingInputMetadata(**base_meta)
    cp = OSSFuzzProject(project_dir)
    extra_env = {}
    if cp.project_language.name == "jvm":
        log.info("Running pov %s with Losan Jazzer instrumentation",pov_path)
        cp = InstrumentedOssFuzzProject(oss_fuzz_project_path=project_dir, instrumentation=JazzerInstrumentation())
        extra_env = {"SHELL_SAN" : "LOSAN"}

    cp.build_runner_image()
    log.info("md5: %s", calculate_md5(pov_path))

    with open(pov_path, "rb") as f:
        pov_content = f.read()

    with open(base_meta_path, "r") as f:
        crashing_input_meta = yaml.safe_load(f.read())
        if "project_name" in crashing_input_meta:
            crashing_input_meta["project_name"] = str(crashing_input_meta["project_name"])
        crashing_input_metadata = CrashingInputMetadata.model_validate(crashing_input_meta)

    function_resolver = RemoteFunctionResolver(crashing_input_metadata.project_name, crashing_input_metadata.project_id)

    base_target_tmp_dir = None

    # Run the pov
    consistently_triggered_sanitizers = None
    triggered_sanitizer_history: List[List[str]] = [] # for each of the runs, what sanitizers were triggered
    significances_history: List[SignificanceEnum] = [] # for each of the runs, what significances were triggered
    seen_stack_traces = {}
    seen_dedup_stack_traces = {}
    # for idx in range(retry_count):
    run_pov_result: Optional[RunPoVResult] = None
    for idx in range(retry_count):
        start = time.time()
        with telemetry_tracer.start_as_current_span("povguy.run_pov") as span:
            run_pov_result: Optional[RunPoVResult] = cp.run_pov(
                harness_name, data_file=pov_path, timeout=timeout,
                function_resolver=function_resolver,
                extra_env=extra_env,
                sanitizer=crash_metadata.sanitizer # the sanitizer that was used to build, this is passed for parsing
            )
            log.info("Run  %s took %s seconds!", idx, time.time() - start)
            pov = run_pov_result.pov
            if pov and pov.crash_report:
                for name, stack_trace in pov.crash_report.stack_traces.items():
                    if name not in seen_stack_traces and stack_trace:
                        seen_stack_traces[name] = stack_trace
            if pov and pov.dedup_crash_report:
                for name, stack_trace in pov.dedup_crash_report.stack_traces.items():
                    if name not in seen_dedup_stack_traces and stack_trace:
                        seen_dedup_stack_traces[name] = stack_trace

        significances_history.append(pov.organizer_crash_eval.significance)
        log.info(
            "#%s: POV %s triggered sanitizers: %s, significance: %s",
            idx,
            pov_path,
            pov.triggered_sanitizers,
            pov.organizer_crash_eval.significance.value,
        )
        if expect_crashing and not pov.crash_report:
            # crash report is a dict, don't want to break the format
            log.critical("#%s: POV %s did not crash!!!", idx, pov_path)
            log.critical("#%s: POV %s stdout: %s", idx, pov_path, run_pov_result.stdout)
            log.critical("#%s: POV %s stderr: %s", idx, pov_path, run_pov_result.stderr)
            triggered_sanitizer_history.append([])
            consistently_triggered_sanitizers = set()
            break
            # TODO: maybe a better way to handle this, since a timeout may lead to no crash
        elif pov.crash_report:
            log.info("#%s: POV %s did crash!!!", idx, pov_path)
            log.info("#%s: POV %s stdout: %s", idx, pov_path, run_pov_result.stdout)
            log.info("#%s: POV %s stderr: %s", idx, pov_path, run_pov_result.stderr)

        if idx == 0:
            assert consistently_triggered_sanitizers is None, "consistently_triggered_sanitizers should be None on first run"
            consistently_triggered_sanitizers = set(pov.triggered_sanitizers)
        else:
            assert consistently_triggered_sanitizers is not None, "consistently_triggered_sanitizers should not be None after first run"
            consistently_triggered_sanitizers &= set(pov.triggered_sanitizers)

        if len(consistently_triggered_sanitizers) == 0:
            break

        triggered_sanitizer_history.append(list(sorted(set(pov.triggered_sanitizers))))


    assert run_pov_result is not None, "run_pov_result should not be None after running pov"

    if run_pov_result and run_pov_result.pov.crash_report:
        for key, stack_trace in seen_stack_traces.items():
            if key not in run_pov_result.pov.crash_report.stack_traces or not run_pov_result.pov.crash_report.stack_traces[key]:
                run_pov_result.pov.crash_report.stack_traces[key] = stack_trace
    if run_pov_result and run_pov_result.pov.dedup_crash_report:
        for key, stack_trace in seen_dedup_stack_traces.items():
            if key not in run_pov_result.pov.dedup_crash_report.stack_traces or not run_pov_result.pov.dedup_crash_report.stack_traces[key]:
                run_pov_result.pov.dedup_crash_report.stack_traces[key] = stack_trace

    if run_pov_result and run_pov_result.pov.exception:
        log.error("POV %s parsing failed: %s", pov_path, run_pov_result.pov.exception)

    log.info("CONSISTENTLY Triggered sanitizers: %s", consistently_triggered_sanitizers)

    # with telemetry_tracer.start_as_current_span("povguy.analysis_graph_upload_run_pov_result") as span:
    #     analysis_run_pov_result = analysis_graph_crash_reports.RunPovResultNode.get_or_create_node_reliable(dict(
    #         key=crash_id,
    #         content=json.loads(run_pov_result.model_dump_json()),
    #         crashes=run_pov_result.pov.crash_report is not None,
    #         crashes_on_base=None,
    #     ), get_properties=dict(
    #         key=crash_id,
    #     ))
    #     analysis_run_pov_result.harness_input.connect(analysis_graph_harness_input)
    #     analysis_run_pov_result.save()

    if len(consistently_triggered_sanitizers) == 0:
        log.error("No valid sanitizers found")
        log.error("Run results: %s", run_pov_result)
        span = get_current_span()
        span.set_status(status_error(), "No valid sanitizers found")
        assert False, "No valid sanitizers found"


    # We don't want this for losan POVS's
    is_losan = (run_pov_result and run_pov_result.pov and run_pov_result.pov.crash_report and run_pov_result.pov.crash_report.losan)
    if all(k == SignificanceEnum.NoSignificantCrashRecognized for k in significances_history):
        if not is_losan:
            log.error("No significant crash recognized in any run")
            log.error("Run results: %s", run_pov_result)
            span = get_current_span()
            span.set_status(status_error(), "No significant crash recognized in any run")
            exit(0)

    if not seen_stack_traces or not [stack_trace for stack_trace in seen_stack_traces.values() if stack_trace]:
        # TODO(finaldeply) revisit this, this is to avoid trying to patch bugs based on bad povreports/poireports
        log.error("No useful stack traces found: %s", seen_stack_traces)
        log.error("Run results: %s", run_pov_result)
        span = get_current_span()
        span.set_status(status_error(), "No useful stack traces found")
        assert False, "No useful stack traces found"


    skip_analysis_graph_upload = is_losan # if losan, skip analysis graph upload

    with telemetry_tracer.start_as_current_span("povguy.analysis_graph_upload_harness_input") as span:
        if not skip_analysis_graph_upload:
            newly_created, analysis_graph_harness_input = HarnessInputNode.create_node(
                harness_info_id=str(crash_metadata.harness_info_id),
                harness_info=crashing_input_metadata,
                content=pov_content,
                crashing=run_pov_result.pov.crash_report is not None,
                pdt_id=crash_id,
            )
            analysis_graph_harness_input.save()

    # Putting this in try and except block to handle the case where the base project fails to run
    try:
        # Since we are in delta mode, we can only submit crashes that only crash on the diff applied project
        if base_project:
            if not base_target_tmp_dir:
                # We need to copy the base project to a tmp dir as we are going to make modifications to it (writing the POV)
                os.makedirs(os.environ['TARGET_TMP_DIR'], exist_ok=True)
                base_target_tmp_dir = tempfile.mkdtemp(dir=os.environ['TARGET_TMP_DIR'])

                assert str(base_target_tmp_dir).startswith('/shared')

                log.info("Base target tmp dir: %s", base_target_tmp_dir)
                subprocess.call([
                    'rsync',
                    '-ra',
                    '--delete',
                    str(base_project).rstrip('/') + '/',
                    str(base_target_tmp_dir).rstrip('/') + '/',
                ])

            cp_base = OSSFuzzProject(Path(base_target_tmp_dir))
            cp_base.build_runner_image()

            for base_idx in range(retry_count // 2 + 1):
                start = time.time()
                with telemetry_tracer.start_as_current_span("povguy.run_pov_base") as span:
                    base_run_pov_result = cp_base.run_pov(
                        harness_name, data_file=pov_path, timeout=timeout
                        , extra_env=extra_env)
                    log.info("Run  %s took %s seconds!", base_idx, time.time() - start)
                    base_pov = base_run_pov_result.pov
                log.info(
                    "#%s: POV %s triggered sanitizers: %s",
                    base_idx,
                    pov_path,
                    base_pov.triggered_sanitizers,
                )
                #analysis_run_pov_result.crashes_on_base = base_pov.crash_report is not None
                #analysis_run_pov_result.save()

                if base_pov.crash_report:
                    # See what to do here as this could possibly be a zero day
                    log.critical("#%s: POV %s crashes in the base project", base_idx, pov_path)
                    log.critical("#%s: POV %s stdout: %s", base_idx, pov_path, base_run_pov_result.stdout)
                    log.critical("#%s: POV %s stderr: %s", base_idx, pov_path, base_run_pov_result.stderr)
                    span = get_current_span()
                    span.set_status(status_error(), "POV crashes in the base project")
                    exit(0)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Handle the case where the base project fails to run
        log.warning("Failed to run the base project: %s", str(e))

        harness_info_id = os.environ.get("HARNESS_INFO_ID")
        if not harness_info_id:
            log.error("HARNESS_INFO_ID environment variable not set, rejecting pov")
            exit(0)

        # Check if we have run the base project successfully before
        try:
            log.info("Checking if we have run the base project successfully before...")
            import requests
            resp = requests.get(f'{os.environ.get("PDT_AGENT_URL")}/data/verify_base_runs/base_run_success/{harness_info_id}', timeout=180)
            if resp.status_code != 200:
                log.error("Failed to check if we have run the base project successfully before, it likely is still being checked. Rejecting POV: %s", resp.text)
                exit(0)
            base_run_success_data = yaml.safe_load(resp.text)
            base_ran_success = base_run_success_data.get('runs', None)
            if base_ran_success is True:
                log.error("Base project did run successfully before, so this error likely is transient, rejecting pov")
                exit(0)
            elif base_ran_success is False:
                log.error("Base project did not run successfully before, so we will let the pov through so we don't block any scoring at all!!!")
            else:
                log.error("We dont know if the base project ran successfully before yet, so reject the pov as we will likely get others later")
                exit(0)
        except Exception as e:
            log.error("Failed to check if we have run the base project successfully before: %s", str(e))
            exit(0)

        log.info("⚠️⚠️⚠️ Proceeding with pov, despite not knowing if it crashes the base")

    all_sanitizers = set(
        [sanitizer for saniset in triggered_sanitizer_history for sanitizer in saniset]
    )
    inconsistent_sanitizers = list(
        sorted(all_sanitizers - consistently_triggered_sanitizers)
    )
    consistent_sanitizers = list(set(consistently_triggered_sanitizers) - { 'libFuzzer: fuzz target exited' }) # remove harness-crash

    full_crash_report = run_pov_result.pov.crash_report

    run_pov_result.pov.crash_report = None  # for deduping
    run_pov_result.pov.extra_context = None  # for deduping
    report = PoVReport(
        inconsistent_sanitizers=inconsistent_sanitizers,
        consistent_sanitizers=consistent_sanitizers,
        **crash_metadata.model_dump(),
        **run_pov_result.pov.model_dump(),
    )

    crash_report = yaml.dump(json.loads(report.model_dump_json())).encode()
    crash_report_md5 = hashlib.md5(crash_report).hexdigest()

    run_pov_result.pov.crash_report = full_crash_report  # restore for full info

    try:
        run_pov_result.pov.clean_invalid_utf8()
    except Exception as e:
        log.error("Failed to clean invalid utf8: %s", str(e))

    with telemetry_tracer.start_as_current_span("povguy.analysis_pov_report_upload") as span:
        if not skip_analysis_graph_upload:
            newly_created, analysis_graph_pov_report = analysis_graph_crash_reports.PoVReportNode.from_crs_utils_pov_report(crash_report_md5, report)
            analysis_graph_pov_report.harness_inputs.connect(analysis_graph_harness_input)
            analysis_graph_pov_report.save()

    representative_full_report = RepresentativeFullPoVReport(
        run_pov_result=run_pov_result,
        original_crash_id=crash_id,
        crash_report_id=crash_report_md5,
        sanitizer_history=triggered_sanitizer_history,
        **report.model_dump(),
    )

    representative_full_report = json.loads(
        representative_full_report.model_dump_json()
    )

    if run_pov_result and run_pov_result.pov and run_pov_result.pov.dedup_crash_report and run_pov_result.pov.dedup_crash_report.losan:
        # dump to the losan report dirs instead of the normal report paths
        out_dedup_pov_report_path = out_dedup_losan_report_path
        out_dedup_pov_report_representative_metadata_path = out_dedup_losan_report_representative_metadata_path
        out_dedup_pov_report_representative_crash_path = out_dedup_losan_report_representative_crash_path
        out_dedup_pov_report_representative_full_report_path = out_dedup_losan_report_representative_full_report_path

    # first, copy the pov to the output directory
    shutil.copy(pov_path, out_dedup_pov_report_representative_crash_path)

    with open(out_dedup_pov_report_representative_metadata_path, "w") as f:
        f.write(
            DedupPoVReportRepresentativeMetadata(
                **crash_metadata.project_info,
                **crash_metadata.build_info,
                **crash_metadata.harness_info,
                build_configuration_id=crash_metadata.build_configuration_id,
                project_harness_metadata_id=crash_metadata.project_harness_metadata_id,
                original_crash_id=crash_id,
                harness_info_id=crash_metadata.harness_info_id,
                consistent_sanitizers=consistent_sanitizers,
            ).model_dump_json()
        )

    # then, copy the metadata to the output directory
    with open(out_dedup_pov_report_representative_full_report_path, "w") as f:
        yaml.dump(representative_full_report, f)

    with open(out_per_crash_full_pov_report_path, "w") as f:
        yaml.dump(representative_full_report, f)

    with open(out_dedup_pov_report_path, "wb") as f:
        f.write(crash_report)

    span = get_current_span()
    span.add_event(
        "povguy.validation_success",
        {"pov": representative_full_report, "crash_report": crash_report},
    )
    span.set_status(status_ok())


def main():
    parser = argparse.ArgumentParser(description="Run a POV with a harness")
    parser.add_argument("--base-meta-path", type=Path, help="Crash metadata yaml file")
    parser.add_argument("--project-dir", type=Path, help="The directory of the oss fuzz project")
    parser.add_argument("--harness-name", type=str, help="The harness name")
    parser.add_argument("--pov-path", type=Path, help="The crashing input path (pov)")
    parser.add_argument("--crash-id", type=str, help="The crash id")

    parser.add_argument("--out-per-crash-full-pov-report-path", type=Path, help="The output path")

    parser.add_argument("--out-dedup-pov-report-path", type=Path, help="The output path")
    parser.add_argument("--out-dedup-pov-report-representative-crash", type=Path, help="The output path")
    parser.add_argument("--out-dedup-pov-report-representative-metadata", type=Path, help="The output path")
    parser.add_argument("--out-dedup-pov-report-representative-full-report", type=Path, help="The output path")

    parser.add_argument("--out-dedup-losan-report-path", type=Path, help="The LOSAN crash output path")
    parser.add_argument("--out-dedup-losan-report-representative-crash", type=Path, help="The output path")
    parser.add_argument("--out-dedup-losan-report-representative-metadata", type=Path, help="The output path")
    parser.add_argument("--out-dedup-losan-report-representative-full-report", type=Path, help="The output path")

    parser.add_argument("--timeout", type=int, default=60, help="The timeout for the POV")
    args = parser.parse_args()
    try:
        BASE_PROJECT_SOURCE_PATH = os.environ.get("BASE_PROJECT_SOURCE_PATH")
        if BASE_PROJECT_SOURCE_PATH is not None and BASE_PROJECT_SOURCE_PATH != "":
            base_project = Path(os.environ['BASE_PROJECT_SOURCE_PATH'])
        else:
            base_project = None
    except:
        # Handle the case where BASE_PROJECT_SOURCE_PATH is not set
        log.warning("BASE_PROJECT_SOURCE_PATH environment variable not set, proceeding without base project.")
        base_project = None

    run_pov(
        base_meta_path=args.base_meta_path,
        project_dir=args.project_dir,
        harness_name=args.harness_name,
        pov_path=args.pov_path,
        crash_id=args.crash_id,

        out_per_crash_full_pov_report_path=args.out_per_crash_full_pov_report_path,

        out_dedup_pov_report_path=args.out_dedup_pov_report_path,
        out_dedup_pov_report_representative_crash_path=args.out_dedup_pov_report_representative_crash,
        out_dedup_pov_report_representative_metadata_path=args.out_dedup_pov_report_representative_metadata,
        out_dedup_pov_report_representative_full_report_path=args.out_dedup_pov_report_representative_full_report,

        out_dedup_losan_report_path=args.out_dedup_losan_report_path,
        out_dedup_losan_report_representative_crash_path=args.out_dedup_losan_report_representative_crash,
        out_dedup_losan_report_representative_metadata_path=args.out_dedup_losan_report_representative_metadata,
        out_dedup_losan_report_representative_full_report_path=args.out_dedup_losan_report_representative_full_report,

        timeout=args.timeout,
        retry_count=5,
        base_project=base_project,
    )
    # retry_count is set to 5 because kernel run_pov may take a long time to run, for tipc, ~2 min for each run


if __name__ == "__main__":
    with telemetry_tracer.start_as_current_span("povguy") as span:
        main()
