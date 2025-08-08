import argparse
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import List

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
import yaml
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver, FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata
from shellphish_crs_utils.models.crs_reports import CrashingInputMetadata
from shellphish_crs_utils.models.ranking import RankedFunction, CodeSwipeRanking
from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel
from agentlib import enable_event_dumping, set_global_budget_limit

from .manager import (
    Scheduler,
    Initializer,
    PostProcessor,
    PreProcessor,
)
from .parser import CodeQLReportParser,  Neo4JBackend, CallGraphParser
from .data.metadata import QuickSeedHarnessInfo
from .utils import setup_oss_fuzz_debug_build, find_absolute_path2
from QuickSeed.parser.path_filter import path_rank, PathFilter
from QuickSeed.llm import QUICKSEED_LLM_BUDGET
init_otel("quickseed", "input_generation", "llm_java_input_generation")
init_llm_otel()
tracer = get_otel_tracer()

_l = logging.getLogger("QuickSeed.main")
_l.setLevel(logging.DEBUG)


import QuickSeed
from QuickSeed.parser import SarifReportParser
from QuickSeed.utils import JAZZER_SANITIZER

def select_warmup_seed_generator_paths(neo4j_raw_paths: list[list[list[CallGraphParser]]], harness_num: int, worker_num: int, sources: list[str]) -> list[list[CallGraphParser]]:
    maximum_paths = harness_num * worker_num
    _l.debug(f"Selecting {maximum_paths} warmup seed generator paths ")
    ranked_paths = path_rank(neo4j_raw_paths, len(neo4j_raw_paths), round_robin_size=3)
    source_filter = PathFilter.starts_with_sources(sources)
    filtered_paths = []
    for p in ranked_paths:
        if source_filter(p):
            filtered_paths.append(p)
    if len(filtered_paths) > maximum_paths:
        filtered_paths = filtered_paths[:maximum_paths]
    filtered_path_set = {tuple(p) for p in filtered_paths}
    for i, raw_paths in enumerate(neo4j_raw_paths):
        raw_path_set = {tuple(p) for p in raw_paths}  # Use a set to remove duplicates
        intersection = filtered_path_set.intersection(raw_path_set)
        remaining_paths = [p for p in raw_paths if tuple(p) not in intersection]
        neo4j_raw_paths[i] = remaining_paths
    return filtered_paths, neo4j_raw_paths
    
def gen_seed(
        target_root: Path, source_root: Path, func_indexer: Path, function_json_dir: Path,
        harnesses: List[CrashingInputMetadata], function_resolver: FunctionResolver,
        available_models: List[str] = None,
        oss_fuzz_debug_build: OSSFuzzProject = None,
        coverage_build_target: Path = None,
        codeql_report: str = '',
        codeswipe_report: str = '',
        local_run: bool = False,
        commit_full_functions_dir: Path | None = None,
        sarif_report: Path | None = None,
        sarif_report_metadata: Path | None = None,
        sink_limit: int = 100
):
    """
    Set up the queueing system for us to send harness request to LLM
    """
    import time
    t1 = time.time()
    jazzer_json_filepath = JAZZER_SANITIZER
    # if available_models is None:
    #     available_models = ["claude-3.7-sonnet", "gpt-4o", "o3-mini"]
    sarif_report_result = None
    codeswipe_funcs = None
    sarif_meta = None
    # We should revisit this, I feel like we need a reflection parser
    reflection_parser = None
    dynamic_call_graph = None
    neo4j_raw_paths = None
    scheduler = Scheduler()
    reflection_output_dir = Path(tempfile.mktemp(prefix="reflection_output_", dir="/tmp"))
    scheduler.start()
    sarif_resolver = None     
    if sarif_report:
        sarif_report_parser = SarifReportParser(sarif_report, function_resolver=function_resolver)
        if len(sarif_report_parser.result) == 0:
            _l.error(f"No results found in SARIF report: {sarif_report}. Exiting.")
            sys.exit(0)
        sarif_resolver = sarif_report_parser.sarif_resolver

        sarif_report_result = sarif_report_parser.result[0] # We assume there is only one result
        sarif_meta = SARIFMetadata.model_validate(yaml.safe_load(Path(sarif_report_metadata).read_text()))
        # sarif_id = sarif_meta.pdt_sarif_id
        locations = sarif_report_result.locations
        sarif_sinks = [location.keyindex for location in locations]
        call_graph_parser = Neo4JBackend(
            cp_root=target_root,
            func_indexer_path=func_indexer,
            func_json_dir=function_json_dir,
            harnesses_file=[harness.harness_source_path for harness in harnesses],
            function_resolver=function_resolver,
            sinks=sarif_sinks,
            oss_fuzz_build=oss_fuzz_debug_build)  
    else:
        with open(codeql_report, "r") as f:
            codeql_report_data = yaml.safe_load(f)
            # Query for last hop to jazzer sink
        with open(codeswipe_report, "r") as f:
            codeswipe_report_data = CodeSwipeRanking.model_validate(yaml.safe_load(f))
        # codeswipe_funcs = [ function['full_funcname'] for function in codeswipe_report_data]
        codeswipe_funcs = []
        codeswipe_func_full_names = []
        for ranked_function in codeswipe_report_data.ranking:
            metadata = ranked_function.metadata
            is_test = metadata.get('skip_test', False).get('is_test', False)
            if is_test:
                _l.debug(f"Skipping test function {ranked_function.full_funcname}")
                continue
            codeswipe_funcs.append(ranked_function.function_index_key)
            codeswipe_func_full_names.append(ranked_function.full_funcname)
        # codeswipe_funcs = [function['function_index_key'] for function in codeswipe_report_data]
        # codeswipe_func_full_names = [function['full_funcname'] for function in codeswipe_report_data]
        harness_paths = []
        for harness in harnesses:
            harness_paths.append(harness.harness_source_path)
        report_parser = CodeQLReportParser(codeql_report_data, upload_analysis_graph=False, function_resolver=function_resolver, local_run=local_run)

        if len(codeswipe_funcs) > sink_limit:
            _l.info(f"Codeswipe report has {len(codeswipe_funcs)} sinks, limiting to {sink_limit}")
            codeswipe_funcs = codeswipe_funcs[:sink_limit]

        # index = [0, 5, 22, 14, 39] # This is the index of the sinks we want to use
        # codeswipe_funcs = [codeswipe_funcs[i] for i in index]
        # codeswipe_func_full_names = [codeswipe_func_full_names[i] for i in index]
        neo4j_backend = Neo4JBackend(
            cp_root=target_root,
            func_indexer_path=func_indexer,
            func_json_dir=function_json_dir,
            harnesses_file=harness_paths,
            function_resolver=function_resolver,
            sinks=codeswipe_funcs, 
            report_parser=report_parser,
            oss_fuzz_build=oss_fuzz_debug_build,
        )
        call_graph_parser = neo4j_backend

        dynamic_call_graph = CallGraphParser(
                function_resolver=function_resolver,
                sources=call_graph_parser.get_sources(),
                codeswipe_func_names=codeswipe_func_full_names,
        )
        
        neo4j_raw_paths = []
        for i, sink in enumerate(codeswipe_funcs):
            paths_to_sink = neo4j_backend.get_paths_for_sink(sink, limit=3)
            if paths_to_sink not in neo4j_raw_paths:
                neo4j_raw_paths.append(paths_to_sink)
            else:
                neo4j_raw_paths.append([]) # This is to ensure we have the same length of neo4j_raw_paths as the number of sinks
        # REVISIT
        preprocessor = PreProcessor(
            scheduler,
            call_graph_parser,
            jazzer_json=jazzer_json_filepath,
            harnesses=harnesses,
            available_models=["gpt-4.1"],
            project_source=source_root,
            function_resolver=function_resolver,
            codeswipe_funcs_ranking_names=codeswipe_func_full_names,
            dynamic_call_graph=dynamic_call_graph,
        )
        preprocessor.submit_tasks_to_scheduler()
        # Change back to the seed generator models once the warmup is done
        preprocessor.available_models = available_models
        if not commit_full_functions_dir:
            # Only enable this in full mode
            selected_paths, remaining_neo4j_raw_paths = select_warmup_seed_generator_paths(neo4j_raw_paths[:40], len(harnesses), scheduler.max_workers, call_graph_parser.get_sources())
            for i, paths in enumerate(remaining_neo4j_raw_paths):
                neo4j_raw_paths[i] = paths
            preprocessor.submit_seed_generator_tasks_while_waiting_for_warm_up(selected_paths)
        post_processor = PostProcessor(
            call_graph_parser,
            scheduler,
            jazzer_json_filepath,
            available_models=available_models,
            coverage_build_target=coverage_build_target,
            harnesses=harnesses,
            oss_fuzz_target=oss_fuzz_debug_build,
            project_source= source_root,
            function_resolver=function_resolver,
            dynamic_call_graph=dynamic_call_graph,
        )
        post_processor.process_result_queue()
        try:
            scheduler.wait_finish()
        except KeyboardInterrupt:
            _l.info("Keyboard interrupt received, stopping the scheduler")
            scheduler.shutdown(wait=False)
            sys.exit(0)

    initializer = Initializer(
        scheduler,
        call_graph_parser,
        reflection_parser=reflection_parser, 
        jazzer_json=jazzer_json_filepath,
        harnesses=harnesses,
        available_models=available_models,
        commit_full_functions_dir=commit_full_functions_dir,
        project_source=source_root,
        reflection_output_dir=reflection_output_dir,
        function_resolver=function_resolver,
        sarif_report_result=sarif_report_result,
        codeswipe_funcs_raking=codeswipe_funcs,
        dynamic_call_graph=dynamic_call_graph,
        sarif_meta=sarif_meta
    )

    initializer.submit_tasks_to_scheduler(neo4j_raw_paths)
    
    post_processor = PostProcessor(
        call_graph_parser,
        scheduler,
        jazzer_json_filepath,
        available_models=available_models,
        coverage_build_target=coverage_build_target,
        harnesses=harnesses,
        oss_fuzz_target=oss_fuzz_debug_build,
        project_source= source_root,
        function_resolver=function_resolver,
        dynamic_call_graph=dynamic_call_graph,
        sarif_resolver=sarif_resolver,
    )

    post_processor.process_result_queue()
    try:
        scheduler.wait_finish()
    except KeyboardInterrupt:
        _l.info("Keyboard interrupt received, stopping the scheduler")
        scheduler.shutdown(wait=False)
        sys.exit(0)
    scheduler.shutdown(wait=True)
    # _l.info(f"💲 Total LLM cost of post processor is {post_processor.total_llm_cost}")
    # total_llm_cost = post_processor.total_llm_cost
    # _l.info(f"💲 Total LLM cost is {total_llm_cost}")
    t2 = time.time()
    _l.info(f"⏰ Total time taken is {t2 - t1} seconds")
    sys.exit(0)


def prepare_harnesses(debug_build: OSSFuzzProject, harness_infos_path: Path, target_root: Path, function_resolver: FunctionResolver):
    harnesses = []
    with open(harness_infos_path) as f:
        harness_infos = yaml.safe_load(f)
    harness_infos = harness_infos["harness_infos"]
    for harness_info_id, harness_info in harness_infos.items():
        harness_info["fuzzer"] = "quickseed"
        harness_info["harness_info_id"] = harness_info_id
        harness_data = CrashingInputMetadata.model_validate(harness_info)
        harness_path = debug_build.get_harness_source_artifacts_path(harness=harness_data.cp_harness_name, resolver=function_resolver)
        assert harness_path is not None, f"Could not find the harness {harness_data.cp_harness_name}"
        if not harness_path.exists():
            if artiphishell_should_fail_on_error():
                assert False, f"Could not find the harness at {harness_path}: {Path(harness_path).exists()}"
            harness_path = find_absolute_path2(target_root, harness_path)
        _l.debug(f"Harness path is {harness_path}")
        harness_dump_name = f"{harness_data.project_name}-{harness_data.cp_harness_name}-{harness_data.harness_info_id}"
        harness_dump_dir = Path(f"/shared/fuzzer_sync/{harness_dump_name}/sync-quickseed/") #${PROJECT_NAME}-${HARNESS_NAME}-${HARNESS_INFO_ID}/
        harness_benign_dir = harness_dump_dir / "queue"
        harness_crash_dir = harness_dump_dir / "crashes"
        harness_benign_dir.mkdir(parents=True, exist_ok=True)
        harness_crash_dir.mkdir(parents=True, exist_ok=True)
        harnesses.append(QuickSeedHarnessInfo(**harness_data.model_dump(), 
                                              harness_source_path=harness_path, 
                                              harness_benign_dir=harness_benign_dir, 
                                              harness_crash_dir=harness_crash_dir))
    return harnesses

def main():
    _l.debug("start the cli")
    parser = argparse.ArgumentParser(
        description="""
        The QuickSeed CLI
        """,
        epilog="""
        Examples:
        QuickSeed --version
        """,
    )
    parser.add_argument(
        "--version", "-v", action="version", version=QuickSeed.__version__
    )
    parser.add_argument("--func-dir", type=Path)
    parser.add_argument("--func-index", type=Path)
    parser.add_argument('--project-metadata', type=lambda s: Path(s) if s else None, help='The path to the project metadata file')
    parser.add_argument(
        "--target-root",
        type=Path,
        help="The root directory of the oss-fuzz target."
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help="The root directory of the source in which the patches will be applied.",
    )
    parser.add_argument('--coverage-build-target', type=Path, help='The path to the coverage build target')
    parser.add_argument('--debug-build-target', type=Path, help='The path to the debug build target')
    parser.add_argument("--harness-infos", type=Path, help="The path to the directory of harness info")
    parser.add_argument("--project-id", type=str, help="The code ql project id")
    parser.add_argument("--local-run", action="store_true", help="Run locally")
    parser.add_argument("--codeql-report", type=str, nargs='?', default=None, help="The path to the codeql report from quickseed_codeql_query task")
    parser.add_argument("--codeswipe-report", type=str, nargs='?', default=None, help="The path to the codeswipe report")
    parser.add_argument("--commit-full-functions-dir", type=str, help="The path to the commit full functions dir")
    # parser.add_argument("--llm-budget", type=float, default=10, help="The budget for the LLM") 
    parser.add_argument("--sarif-report", type=Path, help="The path to the sarif report")
    parser.add_argument("--sarif-report-metadata", type=Path, help="The path to the sarif report metadata")
    args = parser.parse_args()
    target_root = args.target_root
    source_root = args.source_root
    func_dir = args.func_dir
    func_index_path = args.func_index
    if args.project_metadata:
        with open(args.project_metadata) as f:
            augmented_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
    else:
        augmented_metadata = None
    # crash_dir = args.crash_dir
    # benign_dir = args.benign_dir
    local_run = args.local_run
    oss_fuzz_debug_build = args.debug_build_target
    coverage_build_target = args.coverage_build_target
    harness_infos_path = args.harness_infos
    project_id = args.project_id
    
    codeql_raw_report = args.codeql_report
    codeswipe_raw_report = args.codeswipe_report
    commit_full_functions_dir = args.commit_full_functions_dir
    if not commit_full_functions_dir:
        commit_full_functions_dir = None
    # llm_budget = args.llm_budget
    sarif_report = args.sarif_report
    sarif_report_metadata = args.sarif_report_metadata
    enable_event_dumping('./events')
    set_global_budget_limit(
        price_in_dollars=QUICKSEED_LLM_BUDGET,
        exit_on_over_budget=False, # We will handle the budget limits ourselves.
    )
    _l.debug(f"LLM budget is {QUICKSEED_LLM_BUDGET}")

    if not target_root.exists():
        raise FileNotFoundError(f"{target_root} does not exist")
    if not source_root.exists():
        raise FileNotFoundError(f"{source_root} does not exist")

    _l.debug(f"target root is {target_root}")
    _l.debug(f"source root is {source_root}")


    oss_fuzz_debug_build = setup_oss_fuzz_debug_build(oss_fuzz_debug_build, project_id=project_id, augmented_metadata=augmented_metadata, local_run=local_run)
    # coverage_build = setup_oss_fuzz_debug_build(coverage_build_target, project_id=project_id, augmented_metadata=augmented_metadata, local_run=local_run)

    if local_run:
        function_resolver = LocalFunctionResolver(func_index_path, func_dir)
    else:
        function_resolver = RemoteFunctionResolver(cp_name=oss_fuzz_debug_build.project_name, project_id=project_id)

    harnesses = prepare_harnesses(oss_fuzz_debug_build, harness_infos_path, target_root, function_resolver)
    available_models = ["claude-4-sonnet", "o4-mini"] # disable gpt-4.1, o4-mini, "claude-4-sonnet"
    if os.getenv("QUICKSEED_LLM_MODEL") is not None:
        available_models = os.getenv("QUICKSEED_LLM_MODEL").split(",")
        _l.debug(f"Using the model {available_models} from the environment variable QUICKSEED_LLM_MODEL")

    gen_seed(
        Path(target_root),
        Path(source_root),
        func_index_path,
        func_dir,
        harnesses,
        function_resolver,
        available_models=available_models,
        oss_fuzz_debug_build=oss_fuzz_debug_build,
        coverage_build_target=coverage_build_target,
        codeql_report=codeql_raw_report,
        codeswipe_report=codeswipe_raw_report,
        local_run=local_run,
        commit_full_functions_dir=Path(commit_full_functions_dir) if commit_full_functions_dir else None,
        sarif_report=sarif_report if sarif_report else None,
        sarif_report_metadata=sarif_report_metadata if sarif_report_metadata else None,
    )

    sys.exit(0)


if __name__ == "__main__":
    with tracer.start_as_current_span("quickseed") as span:
        main()
        span.set_status(status_ok())
