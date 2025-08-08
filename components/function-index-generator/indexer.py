import argparse  # Import argparse module for command-line parsing
import functools
import json
import logging

from tqdm import tqdm  # Import tqdm for progress bar
from typing import List, Dict, Optional
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

from shellphish_crs_utils.models import (
    FunctionIndex,
    ReducedFunctionIndex,
    CommitToFunctionIndex,
    SignatureToFile,
    FunctionsByFile,
)

from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
    get_current_span,
)

init_otel("function-index-generator", "static_analysis", "function_index_generator")
tracer = get_otel_tracer()
# Set up logging
logging.basicConfig(
    level="INFO",  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(message)s",
    datefmt="[%X]",
)

log = logging.getLogger("FIG")


@tracer.start_as_current_span("function_index_generator.process_file_for_meta_index")
def process_file_for_meta_index(
    input_dir: Path, functions_by_file_json_path: Path, file_path: Path
) -> Optional[ReducedFunctionIndex]:
    try:
        f_index = FunctionIndex.model_validate_json(file_path.read_text())
    except Exception as e:
        log.critical("Error processing file: %s", file_path)
        log.critical("Error: %s", e)
        log.critical("File content: %s", file_path.read_text())
        return None

    function_signature = f"{f_index.target_container_path}:{f_index.start_line}:{f_index.start_column}::{f_index.signature}"
    line_map = (
        {
            f_index.start_line + i: line
            for i, line in enumerate(f_index.code.split("\n"))
        }
        if functions_by_file_json_path
        else None
    )

    reduced_index = ReducedFunctionIndex(
        func_name=f_index.funcname,
        function_signature=function_signature,
        filename=f_index.filename,
        start_line=f_index.start_line,
        end_line=f_index.end_line,
        start_column=f_index.start_column,
        end_column=f_index.end_column,
        start_offset=f_index.start_offset,
        end_offset=f_index.end_offset,
        line_map=line_map,
        indexed_jsons_relative_filepath=file_path.relative_to(input_dir),
        target_container_path=f_index.target_container_path,
        focus_repo_relative_path=f_index.focus_repo_relative_path,
    )
    return reduced_index


def parallel_merge_dicts(
    all_indicies: List[ReducedFunctionIndex], chunk_size
) -> Dict[str, Path]:
    chunks = [
        all_indicies[i : i + chunk_size]
        for i in range(0, len(all_indicies), chunk_size)
    ]

    final_dict = {}
    for chunk in tqdm(chunks, desc="Merging function indicies", total=len(chunks)):
        final_dict |= {
            index.function_signature: index.indexed_jsons_relative_filepath
            for index in chunk
        }

    return final_dict


def commit_to_index_json(input_dir: Path, target_function_index: Path):
    num_cpus = cpu_count()
    out_json = {}
    for commit in input_dir.iterdir():
        log.info("Processing commit: %s", commit.name)
        files = set(commit.rglob("**/*.json"))
        chunk_size = min(512, (len(files) // num_cpus) + 1)
        log.info("Number of CPUs used: %s, Chunk size: %s", num_cpus, chunk_size)

        with Pool(processes=num_cpus) as pool:
            partial_func = functools.partial(
                process_file_for_meta_index, input_dir, None
            )
            results_index: List[ReducedFunctionIndex] = list(
                tqdm(
                    pool.imap_unordered(partial_func, files, chunksize=chunk_size),
                    total=len(files),
                )
            )
        out_json[commit.name] = {
            index.function_signature: str(index.indexed_jsons_relative_filepath)
            for index in results_index
        }
        
    with open(target_function_index, "w") as f:
        log.info("Writing index to JSON")
        validated_data = CommitToFunctionIndex(
            commit_to_index_info=out_json
        ).model_dump()["commit_to_index_info"]
        json.dump({
            commit: {key: str(path) for key, path in commit_info.items()}
             for commit, commit_info in validated_data.items()
             }, f, indent=4)
        log.info("Index written to JSON successfully")


def full_index_json(
    input_dir: Path, target_function_index: Path, functions_by_file_json_path: Path
):
    num_cpus = cpu_count()

    log.info("Compiling code database for directory: %s", input_dir)
    files = list(input_dir.rglob("**/*.json"))
    chunk_size = min(512, (len(files) // num_cpus) + 1)
    log.info("Number of CPUs used: %s, Chunk size: %s", num_cpus, chunk_size)

    with Pool(processes=num_cpus) as pool:
        partial_func = functools.partial(
            process_file_for_meta_index, input_dir, functions_by_file_json_path
        )
        function_indicies = []
        for func_index in tqdm(
            pool.imap_unordered(partial_func, files, chunksize=chunk_size),
            desc="Processing File Indicies",
            total=len(files),
        ):
            if not func_index:
                continue
            function_indicies.append(func_index)

    source_index = defaultdict(list)
    for func_index in tqdm(function_indicies, desc="Building index file"):
        source_index[
            str(func_index.target_container_path.resolve())
        ].append(func_index)

    validated_data = json.loads(
        FunctionsByFile(func_by_file=source_index).model_dump_json()
    )["func_by_file"]
    functions_by_file_json_path.write_text(json.dumps(validated_data, indent=4))

    log.info("Writing index JSON to %s", target_function_index)
    combined_dict = parallel_merge_dicts(function_indicies, chunk_size)
    with target_function_index.open("w") as f:
        validated_data = json.loads(
            SignatureToFile(sig_to_file=combined_dict).model_dump_json()
        )["sig_to_file"]
        json.dump(validated_data, f, indent=4)
        log.info("Index written to JSON successfully")


def main():
    parser = argparse.ArgumentParser(
        description="Compile a code database from JSON files."
    )
    parser.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["full", "commit"],
        help="Mode of compilation full or commit",
    )
    parser.add_argument(
        "--input-target-functions-json-dir",
        type=Path,
        required=True,
        help="Input directory containing JSON files",
    )
    parser.add_argument(
        "--output-target-functions-index",
        required=True,
        type=Path,
        help="Output path for target functions index",
    )
    parser.add_argument(
        "--output-functions-by-file-index-json",
        required=False,
        type=Path,
        default=None,
        help="Output path for source index JSON",
    )
    args = parser.parse_args()

    span = get_current_span()
    span.set_attribute("function_index_generator.mode", str(args.mode))
    if args.mode == "commit":
        commit_to_index_json(
            args.input_target_functions_json_dir, args.output_target_functions_index
        )
    else:
        full_index_json(
            input_dir=args.input_target_functions_json_dir,
            target_function_index=args.output_target_functions_index,
            functions_by_file_json_path=args.output_functions_by_file_index_json,
        )


if __name__ == "__main__":
    with tracer.start_as_current_span("function_index_generator") as span:
        main()
        span.set_status(status_ok())
