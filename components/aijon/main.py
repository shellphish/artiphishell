import os
import time
import shutil
import zipfile
import argparse
from pathlib import Path
from loguru import logger
from tempfile import mkdtemp, NamedTemporaryFile
from multiprocessing import Pool
from collections import defaultdict

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from crs_telemetry.utils import init_otel, get_otel_tracer, init_llm_otel
from aijon_lib import (
    PatchPOI,
    SarifPOI,
    CodeSwipePOI,
    instrument_code_with_ijon,
    apply_llm_response,
    ag_utils,
)

CUR_DIR = Path(__file__).parent.absolute()
POI_OBJ = None

init_otel("aijon-instrumentation", "program_analysis", "llm_instrumentation")
init_llm_otel()
tracer = get_otel_tracer()


def parse_args():
    parser = argparse.ArgumentParser(description="Instrument code with IJON.")
    parser.add_argument(
        "--target_source",
        "-t",
        type=Path,
        required=True,
        help="Path to the target source directory.",
    )
    parser.add_argument(
        "--target_functions_json_dir",
        type=Path,
        required=True,
        help="Path to the target functions JSON directory.",
    )
    parser.add_argument(
        "--full_function_indices",
        type=Path,
        required=True,
        help="Path to the full function indices JSON file.",
    )
    parser.add_argument(
        "--project_name",
        type=str,
        required=False,
        help="The name of the project being instrumented.",
    )
    parser.add_argument(
        "--project_id",
        type=str,
        required=False,
        help="The ID of the project being instrumented.",
    )
    parser.add_argument(
        "--destination",
        "-d",
        type=Path,
        required=False,
        help="The path to store the output.",
    )
    parser.add_argument(
        "--diff_only",
        action="store_true",
        required=False,
        help="Only store the diff of the annotated code. This will not store the full code.",
    )
    poi = parser.add_mutually_exclusive_group(required=True)
    poi.add_argument(
        "--codeswipe_report",
        type=Path,
        help="Path to the CodeSwip report.",
    )
    poi.add_argument(
        "--sarif_report",
        type=Path,
        help="Path to the SARIF report.",
    )
    poi.add_argument(
        "--patch_report",
        type=Path,
        help="Path to the patch report.",
    )
    return parser.parse_args()


def test_simple():
    maze_path = CUR_DIR / "artifacts" / "big-maze.c"
    maze_code = maze_path.read_text()
    instrumented_code = instrument_code_with_ijon(maze_code)
    print(instrumented_code)


def worker_function(
    poi: dict,
    modified_source_dir: Path,
):
    """
    Worker function to process a single Point of Interest (POI).
    """
    global POI_OBJ
    poi_obj = POI_OBJ

    harness_input_dict = defaultdict(list)
    allow_list_funcs = list()
    total_cost = 0.0
    with tracer.start_as_current_span("aijon.instrument.poi"):
        logger.info(f"Processing POI for function {poi['function_index_key']}")
        if ag_utils.verify_func_index_in_ag(poi["function_index_key"]):
            sink_funcindex = poi["function_index_key"]
        else:
            try:
                sink_funcindex = poi_obj.funcindex_to_ag_funcindex(
                    poi["function_index_key"]
                )
            except ValueError:
                logger.warning(
                    f"🤡 Warning: Function index {poi['function_index_key']} not found in the Analysis Graph.",
                )
                return

        logger.debug(
            f"Finding closest covered caller for sink function {sink_funcindex}"
        )

        # Step 2 is to query the Analysis Graph to find the closest covered parent
        if not ag_utils.check_function_covered(sink_funcindex):
            # Sink function is not covered, find the closest covered caller
            closest_covered_caller, call_path = ag_utils.find_closest_covered_caller(
                sink_funcindex=sink_funcindex
            )
            if not closest_covered_caller:
                # No closest covered caller found, try to find longest paths to the sink function
                logger.warning(
                    f"🤡 Warning: No covered caller found for sink function {sink_funcindex}",
                )

                logger.info(
                    f"Final attempt at finding paths to sink function {sink_funcindex}"
                )
                call_path = ag_utils.find_paths_to_sink(sink_funcindex)

                if len(call_path) == 0:
                    logger.warning(
                        f"🎪 Warning: No paths found to sink function {sink_funcindex}."
                    )
                    return

        else:
            # Sink function is covered, so we can use it directly
            closest_covered_caller, call_path = sink_funcindex, list()

        if closest_covered_caller:
            logger.debug(
                f"Finding harness name and inputs for function {closest_covered_caller}"
            )
            harness_input_dict.update(
                ag_utils.get_harness_name_and_inputs(closest_covered_caller)
            )

        call_path_func_indices = list()
        if len(call_path) == 0:
            call_path_func_indices.append(closest_covered_caller)
        else:
            for func_index in call_path:
                try:
                    call_path_func_indices.append(
                        poi_obj.ag_funcindex_to_funcindex(func_index["identifier"])
                    )
                except ValueError:
                    logger.warning(
                        f"🤡 Could not find function index for {func_index['identifier']}."
                    )
                    continue

        try:
            resolved_sinkfunc_index = poi_obj.get_function_index_from_poi(
                poi["function_index_key"]
            )
        except ValueError:
            logger.warning(
                f"🤡 Warning: Could not resolve function index for {poi['function_index_key']}. Skipping POI"
            )
            if artiphishell_should_fail_on_error():
                assert False, (
                    f"Failed to resolve function index {poi['function_index_key']}"
                )
            return

        resolved_caller_indices = list()
        for func_index in call_path_func_indices:
            try:
                resolved_caller_indices.append(
                    poi_obj.get_function_index_from_poi(func_index).funcname
                )
            except ValueError:
                logger.warning(
                    f"🤡 Warning: Could not resolve function index for {func_index}. Skipping."
                )
                if artiphishell_should_fail_on_error():
                    assert False, f"Failed to resolve function index {func_index}"
                continue

        allow_list_funcs.extend(resolved_caller_indices)

        # Step 3 is to instrument the code with IJON
        try:
            logger.info(f"Instrumenting code @ {modified_source_dir} with POI {poi}")
            cost, llm_response = instrument_code_with_ijon(
                poi,
                resolved_sinkfunc_index,
                modified_source_dir,
            )
            total_cost += cost
            logger.debug(f"Cost of instrumenting code with IJON: {total_cost}")
        except ValueError:
            logger.warning(
                f"🤡 Warning: Could not instrument code with IJON for POI {poi}. Skipping."
            )
            return
        except Exception as e:
            logger.exception(
                f"🤡 UNEXPECTED EXCEPTION {e}"
            )
            return

    return {
        "total_cost": cost,
        "filename": resolved_sinkfunc_index.focus_repo_relative_path,
        "function_line_number": resolved_sinkfunc_index.start_line,
        "llm_response": llm_response,
        "allow_list_funcs": allow_list_funcs,
        "harness_input_dict": harness_input_dict,
    }


def main(
    target_source: Path,
    report_path: Path,
    poi_obj: CodeSwipePOI | SarifPOI | PatchPOI,
) -> tuple[Path, list[str], dict[str, list[str]]]:
    """Main function to instrument code with IJON.

    Args:
        target_source (Path): Path to the target source directory.
        report_path (Path): Path to the report file.
        poi_obj (CodeSwipePOI | SarifPOI | PatchPOI): POI object to handle different report formats.

    Returns
        Path: Path to the instrumented code directory.
    """
    global POI_OBJ
    POI_OBJ = poi_obj

    temp_dir = mkdtemp()
    modified_source_dir = Path(temp_dir)
    shutil.copytree(
        target_source,
        modified_source_dir,
        dirs_exist_ok=True,
        symlinks=True,
        ignore_dangling_symlinks=True,
    )

    # Step 1 is to parse the report and add POIs to the POI object
    poi_obj.add_poi(report_path)
    if poi_obj.empty:
        shutil.rmtree(modified_source_dir)
        raise ValueError("☣️ AIJON instrumentation failed since no POIs were found.")

    global_cost = 0.0
    global_allow_list_funcs = set()
    global_harness_input_dict = defaultdict(list)

    with Pool(processes=20) as pool:
        logger.info(
            f"Starting parallel processing of {len(poi_obj.get_all_pois())} POIs."
        )
        results = pool.starmap(
            worker_function,
            [(poi, modified_source_dir) for poi in poi_obj.get_all_pois()],
        )

        logger.info("Aggregating results from workers.")

        global_cost = sum(x.get("total_cost", 0.0) for x in results if x is not None)
        logger.info(f"Total cost of instrumentation: {global_cost}")

        for worker_data in sorted((r for r in results if r), key=lambda x: -x["function_line_number"]):
            logger.trace(f"Processing results from worker {worker_data}")
            if worker_data is None:
                logger.warning("🤡 Warning: Worker data is None. Skipping.")
                continue
            filename = worker_data["filename"]
            function_line_number = worker_data["function_line_number"]
            llm_response = worker_data["llm_response"]
            allow_list_funcs = worker_data["allow_list_funcs"]
            harness_input_dict = worker_data["harness_input_dict"]

            logger.debug(f"Applying patch:\n{filename=}\n{function_line_number=}\n{llm_response=}")

            try:
                target_file_path = modified_source_dir / filename
                original_code = target_file_path.read_text()
                modified_code, bad_blocks, num_success = apply_llm_response(
                    original_code=original_code, llm_response=llm_response,
                    line_offset=function_line_number-1, # stupid clang-indexer 1-indexing
                    language=os.getenv("LANGUAGE")
                )
                target_file_path.write_text(modified_code)
            except Exception as e:
                # This can happen if we modify the same file multiple times
                logger.warning(
                    f"🤡 Search and replace failed for {filename}. {e} - Skipping."
                )
                continue

            global_allow_list_funcs.update(allow_list_funcs)
            global_harness_input_dict.update(harness_input_dict)

    return modified_source_dir, global_allow_list_funcs, global_harness_input_dict


if __name__ == "__main__":
    args = parse_args()

    with tracer.start_as_current_span("aijon.main") as span:
        target_source = args.target_source
        assert target_source.is_dir(), (
            f"Target source {target_source} is not a directory."
        )

        full_function_indices = args.full_function_indices

        target_functions_json_dir = args.target_functions_json_dir

        assert full_function_indices.is_file(), (
            f"Need full_function_indices if project_id or project_name is not provided."
        )
        assert target_functions_json_dir.is_dir(), (
            f"Need target_functions_json_dir if project_id or project_name is not provided."
        )

        project_id = args.project_id
        project_name = args.project_name

        if args.codeswipe_report:
            report_path = args.codeswipe_report
            POI_obj = CodeSwipePOI(
                project_id=project_id,
                project_name=project_name,
                full_function_indices_path=full_function_indices,
                target_functions_json_dir=target_functions_json_dir,
            )
        elif args.sarif_report:
            report_path = args.sarif_report
            POI_obj = SarifPOI(
                project_id=project_id,
                project_name=project_name,
                full_function_indices_path=full_function_indices,
                target_functions_json_dir=target_functions_json_dir,
            )
        elif args.patch_report:
            report_path = args.patch_report
            POI_obj = PatchPOI(
                project_id=project_id,
                project_name=project_name,
                full_function_indices_path=full_function_indices,
                target_functions_json_dir=target_functions_json_dir,
            )

        if args.destination:
            destination = args.destination
            if not destination.is_dir():
                logger.info(f"🔮 Creating directory {destination}.")
                destination.mkdir(parents=True, exist_ok=True)
        else:
            tempdir = mkdtemp()
            destination = Path(tempdir)

        allowlist_file = destination / "aijon_allowlist.txt"

        logger.info(f"Instrumentation Artifacts will be saved to {destination}. ")

        assert report_path.is_file(), f"Report {report_path} does not exist."

        logger.info(
            f"🎠 Instrumenting source @ {target_source} with report @ {report_path}."
        )
        ctr = 0
        while True:
            if ctr == 10:
                raise RuntimeError("☣️ AIJON instrumentation failed 10 times.")

            with tracer.start_as_current_span("aijon.instrument"):
                try:
                    modified_source, allow_list_funcs, harness_input_dict = main(
                        target_source, report_path, POI_obj
                    )
                except ValueError:
                    logger.error("🤡 No POI's found. Exiting")
                    raise RuntimeError(
                        "☣️ AIJON instrumentation failed since no POIs were found."
                    )

            if len(allow_list_funcs) > 0:
                break

            logger.warning("🫂 AIJON instrumentation failed. Retrying in 10 minutes.")
            POI_obj.remove_all_pois()
            time.sleep(600)
            ctr += 1

        logger.success("🎊 AIJON instrumentation succeeded.")

        if args.diff_only:
            diff_contents = ag_utils.get_diff_contents(modified_source)
            diff_file = destination / "aijon_instrumentation.patch"
            if len(diff_contents) == 0:
                raise ValueError("☣️ Nothing to diff.️")
            else:
                with NamedTemporaryFile(mode="w+", delete=True) as temp_file:
                    temporary_diff_file = Path(temp_file.name)
                    temporary_diff_file.write_text(diff_contents)
                    logger.info("Verifying diff contents")
                    verified_diff = ag_utils.verify_diff_contents(
                        temporary_diff_file, target_source
                    )
                diff_file.write_text(verified_diff)
                logger.success(f"🎀 Diff file is saved to {diff_file}.")
        else:
            shutil.copytree(modified_source, destination, dirs_exist_ok=True)
            logger.success(f"🎁 Instrumented code is saved to {destination}.")

        if len(allow_list_funcs) > 0:
            allowlist_file.write_text("\n".join(allow_list_funcs) + "\n")
            logger.success(
                f"📝 Allowlist file is saved to {allowlist_file} with {len(allow_list_funcs)} functions."
            )

        with tracer.start_as_current_span("aijon.harness_input"):
            if len(harness_input_dict) == 0:
                logger.warning(
                    "🤡 No harness inputs found. Skipping harness input generation."
                )
            for harness_name in harness_input_dict:
                logger.info(
                    f"Found {len(harness_input_dict[harness_name])} inputs for harness: {harness_name}"
                )
                input_file_dir = destination / harness_name
                input_file_dir.mkdir(parents=True, exist_ok=True)
                seed_corpus_file = destination / f"{harness_name}_seed_corpus.zip"
                with zipfile.ZipFile(seed_corpus_file, "w") as zipf:
                    for idx, input_bytes in enumerate(harness_input_dict[harness_name]):
                        input_file = input_file_dir / f"{idx}"
                        input_file.write_bytes(input_bytes)
                        zipf.write(input_file, arcname=input_file.name)

                shutil.rmtree(input_file_dir)
                logger.success(
                    f"🎁 Seed corpus for harness {harness_name} is saved to {seed_corpus_file}."
                )

        shutil.rmtree(modified_source)
