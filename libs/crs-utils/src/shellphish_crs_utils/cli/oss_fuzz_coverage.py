import argparse
import yaml
import os
import glob
import sys
import time

from collections import defaultdict
from pathlib import Path

from coveragelib import Tracer
from coveragelib.parsers import C_FunctionCoverageParser_Profraw, C_LineCoverageParser_LLVMCovHTML, Java_FunctionCoverageParser_Jacoco
from coveragelib.parsers.line_coverage import Java_LineCoverageParser_Jacoco
from analysis_graph.api.dynamic_coverage import register_harness_input_file_coverage, register_harness_input_function_coverage
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, FunctionResolver
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "dynamic_analysis", "oss_fuzz.coverage")
tracer = get_otel_tracer()

def main():
    with tracer.start_as_current_span("oss_fuzz.coverage") as span:
        # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
        parser_class = {
            "c": {
                "function-lines": C_LineCoverageParser_LLVMCovHTML(),
                "lines": C_LineCoverageParser_LLVMCovHTML(),
                "functions": C_FunctionCoverageParser_Profraw(),
            },
            "c++": {
                "function-lines": C_LineCoverageParser_LLVMCovHTML(),
                "lines": C_LineCoverageParser_LLVMCovHTML(),
                "functions": C_FunctionCoverageParser_Profraw(),
            },
            "jvm": {
                "function-lines": Java_LineCoverageParser_Jacoco(),
                "lines": Java_LineCoverageParser_Jacoco(),
                "functions": Java_FunctionCoverageParser_Jacoco(),
            },
        }
        parser = argparse.ArgumentParser(description='Build instrumented projects')
        parser.add_argument('--merge', action='store_true', help='Merge the coverage reports for all seeds into one')
        parser.add_argument('-f', '--coverage-format', type=str, default='functions', help='Coverage format to use')
        parser.add_argument("--full-functions-index", type=Path, default=None, help="Path to the full functions index (required for function-lines coverage)")
        parser.add_argument("--full-functions-jsons", type=Path, default=None, help="Path to the full functions jsons dir (required for function-lines coverage)")
        parser.add_argument('--output', type=Path, default=None, help='Output path')
        parser.add_argument('--analysis-graph-upload', action='store_true', help='Upload the coverage data to the analysis graph')
        parser.add_argument('--harness-info-id', type=str, default=None, help='Harness info id to upload the coverage data to the analysis graph')
        parser.add_argument('--harness-info', type=Path, default=None, help='Path to the harness info to upload the coverage data to the analysis graph')
        parser.add_argument('target_path', type=Path, help='Path to the oss-fuzz project directory')
        parser.add_argument('harness_name', type=str, help='Name of the harness to collect coverage for, can be supplied multiple times')
        parser.add_argument('input_dir', type=Path, help='Path to the input directory')
        args = parser.parse_args()

        if args.coverage_format == "function-lines":
            assert args.full_functions_index is not None, "Full functions index is required for function-lines coverage"
            assert args.full_functions_jsons is not None, "Full functions jsons dir is required for function-lines coverage"

            if args.analysis_graph_upload:
                assert args.harness_info_id is not None, "Harness info id is required for analysis graph upload"
                assert args.harness_info is not None, "Harness info is required for analysis graph upload"

        assert args.input_dir.is_dir(), f"Input directory {args.input_dir} does not exist"
        seeds = list(args.input_dir.glob('*'))

        # Make sure that all the file in the input directory are valid
        for seed in seeds:
            if not seed.is_file():
                print(f"Invalid seed file: {seed}")
                print("All files in the input directory must be valid files (not directories)")
                sys.exit(1)

        project = OSSFuzzProject(args.target_path)
        parser = parser_class[project.project_metadata.language][args.coverage_format]

        import ipdb
        with ipdb.slaunch_ipdb_on_exception():
            with Tracer(args.target_path, args.harness_name, aggregate=args.merge, parser=parser) as tracer:
                res = tracer.trace(*seeds)

                if args.coverage_format == "function-lines":

                    resolver = LocalFunctionResolver(args.full_functions_index, args.full_functions_jsons)
                    if args.analysis_graph_upload:
                        # Upload the function coverage to the analysis graph
                        start_time = time.time()
                        res = resolver.get_function_coverage(res)
                        coverage_resolved_time = time.time()
                        print(f"Time taken to resolve function coverage: {coverage_resolved_time - start_time:.2f} seconds")
                        with open(args.harness_info, 'r') as f:
                            harness_info = HarnessInfo.model_validate(yaml.safe_load(f))
                        for seed in seeds:
                            with open(seed, 'rb') as f:
                                register_harness_input_file_coverage(args.harness_info_id, harness_info, f.read(), False, resolver, res)
                        upload_time = time.time()
                        print(f"Time taken to upload function coverage: {upload_time - coverage_resolved_time:.2f} seconds")

                    start_time = time.time()
                    res = {key: list([v.model_dump() for v in vals]) for key, vals in resolver.get_function_coverage(res).items()}
                    end_time = time.time()
                    print(f"Time taken to resolve function coverage: {end_time - start_time:.2f} seconds")

                with open(args.output, 'w') as f:
                    f.write(yaml.dump(res))
                    
                # from rich import print
                # print(res)