import argparse
import json
import yaml
import tempfile
import shutil
import time
import re
import statistics
import multiprocessing

from typing import Generator
from pathlib import Path

from rich.console import Console
from rich.table import Table

from shellphish_crs_utils.models.crs_reports import POIReport
from shellphish_crs_utils.models.crs_reports import RootCauseReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from debug_lib.agent import run_agent

BACKUP_FOLDER = Path(__file__).parent.absolute() / "backups"
OUTPUT_FOLDER = BACKUP_FOLDER.parent / "output"
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)

def get_args_from_backup(backup_info: dict, shared_path: Path) -> dict:
    """
    Get the links from the backup folder.
    """
    def compare_cpv_and_poi(cpv: dict, poi: dict):
        """
        Compare the CPV and POI.
        """
        if cpv["harness"][0] != poi.get("cp_harness_name"):
            return False
        
        if all(x not in poi["consistent_sanitizers"] for x in cpv["consistent_sanitizers"]):
            return False
        for token_type in cpv["dedup_tokens"]:
            if all(x not in poi["additional_information"]["asan_report_data"]["dedup_tokens"].get(token_type, []) for x in cpv["dedup_tokens"][token_type]):
                return False
        return True
    backup_dir = BACKUP_FOLDER / backup_info["backup"]
    cpvs = backup_info["cpvs"].copy()
    cpv_mapping = {}
    for poi_report_path in (backup_dir / "poiguy.poi_report").iterdir():
        poi_report_text = poi_report_path.read_text()
        poi_report = yaml.safe_load(poi_report_text)
        for cpv_num, cpv in cpvs.items():
            if compare_cpv_and_poi(cpv, poi_report):
                cpv_mapping[cpv_num] = poi_report
                break

        else:
            continue
        cpvs.pop(cpv_num)
        if not cpv:
            break
    cpv_args = {}
    for cpv_num, poi_report in cpv_mapping.items():
        print("Making args for cpv_num", cpv_num)
        crashing_input_path = backup_dir / "dyva_agent.crashing_input" / poi_report["crash_report_id"]
        build_artifact_path = backup_dir / "dyva_build.dyva_build_artifact" / poi_report["build_configuration_id"]
        oss_fuzz_project_path = backup_dir / "dyva_agent.oss_fuzz_project" / poi_report["project_id"]

        assert crashing_input_path.exists(), f"Crashing input path does not exist: {crashing_input_path}"
        assert build_artifact_path.exists(), f"Build artifact path does not exist: {build_artifact_path}"
        assert oss_fuzz_project_path.exists(), f"OSS Fuzz project path does not exist: {oss_fuzz_project_path}"

        tmp_shared_path = tempfile.mkdtemp(dir=shared_path)
        temp_oss_fuzz_project_dir = Path(tmp_shared_path) / "projects" / poi_report["project_name"]
        temp_oss_fuzz_work_dir = (temp_oss_fuzz_project_dir / "artifacts" / "work")
        temp_oss_fuzz_work_dir.mkdir(parents=True, exist_ok=True)
        
        shutil.copyfile(crashing_input_path, temp_oss_fuzz_work_dir / "pov_input")

        shutil.copytree(oss_fuzz_project_path, tmp_shared_path, dirs_exist_ok=True, symlinks=True)
        shutil.copytree(build_artifact_path, temp_oss_fuzz_project_dir / "artifacts", dirs_exist_ok=True, symlinks=True)

        real_poi_report = POIReport.model_validate(poi_report)
        oss_fuzz_project = OSSFuzzProject(
            temp_oss_fuzz_project_dir,
            temp_oss_fuzz_project_dir / "artifacts" / "built_src",
        )
        args = {
            "oss_fuzz_project": oss_fuzz_project,
            "crashing_input": crashing_input_path,
            "poi_report": real_poi_report,
            "output_path": OUTPUT_FOLDER / f"output_{cpv_num}",
            "arbitrary_crash": False,
            "max_iterations": 30,
        }
        cpv_args[cpv_num] = args
    return cpv_args

def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description="Run root cause analysis ablation on CPVs.")
    parser.add_argument(
        "--fresh",
        action="store_true",
        default=False,
        help="Run the root cause analysis on all CPVs, ignoring previous results.",
    )
    parser.add_argument(
        "--skip-run",
        action="store_true",
        default=False,
        help="Skip checking for missing results and print the results of the root cause analysis.",
    )
    parser.add_argument(
        "--retry-models",
        nargs="+",
        default=[],
        help="List of models to retry.",
    )
    parser.add_argument(
        "--single-thread",
        action="store_true",
        default=False,
        help="Run the root cause analysis on a single thread.",
    )
    return parser.parse_args()

def run_agent_worker(args_tuple):
    cpv_num, model, cpv_args = args_tuple
    exception = None
    root_cause = None
    tools_used = None
    cost = None
    try:
        start = time.time()
        root_cause, tools_used, cost = run_agent(
            oss_fuzz_project=cpv_args["oss_fuzz_project"],
            poi_report=cpv_args["poi_report"],
            crashing_input=cpv_args["crashing_input"],
            output_path=cpv_args["output_path"],
            arbitrary_crash=cpv_args["arbitrary_crash"],
            max_iterations=cpv_args["max_iterations"],
            model=model,
            # strategy="three_agent",
        )
    except Exception as e:
        exception = str(e)
    end = time.time()
    duration = end - start
    return (cpv_num, model, duration, exception, root_cause, tools_used, cost)

def main(fresh: bool = False, skip_run: bool = False, retry_models: list[str] = None, single_thread: bool = False):
    console = Console(record=True, width=200)
    retry_models = retry_models or []
    final_results = {}
    models = ["gpt-4.1-mini", 
              "gpt-4.1-nano", 
              "gpt-4.1", 
              "claude-3.5-sonnet", 
              "claude-3.7-sonnet", 
              "claude-3-haiku", 
              "claude-4-sonnet", 
              "gemini-2.5-pro", 
              "gemini-2.0-flash", 
              "gemini-2.0-flash-lite", 
              "gemini-2.5-pro-preview"]
    result_json = BACKUP_FOLDER.parent / "final_results.json"
    if result_json.exists():
        with open(result_json, "r") as f:
            final_results = json.load(f)

    jobs = []
    if not skip_run:
        shared_path = Path("/shared/dyva/oss_fuzz")
        shared_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=shared_path) as tempdir:
            for backup_json in BACKUP_FOLDER.glob("*.json"):
                args = get_args_from_backup(json.loads(backup_json.read_text()), shared_path=tempdir)
                for cpv_num, cpv_args in args.items():
                    for model in models:
                        if retry_models:
                            if model not in retry_models:
                                continue
                        else:
                            if not fresh and final_results.get(cpv_num) and any(result["model"] == model for result in final_results[cpv_num]):
                                continue
                        # NOTE: If cpv_args contains non-picklable objects, you may need to serialize/deserialize here.
                        jobs.append((cpv_num, model, cpv_args))

            with multiprocessing.Pool(processes=1 if single_thread else ((multiprocessing.cpu_count()*3)//4)) as pool:
                for result in pool.imap_unordered(run_agent_worker, jobs):
                    cpv_num, model, duration, exception, root_cause, tools_used, cost = result
                    if cpv_num not in final_results:
                        final_results[cpv_num] = []
                    if model in retry_models:
                        final_results[cpv_num] = [result for result in final_results[cpv_num] if result["model"] != model]
                    final_results[cpv_num].append({
                        "duration": duration,
                        "error": exception,
                        "root_cause": root_cause.model_dump(mode='json') if root_cause else None,
                        "tools_used": tools_used,
                        "cost": cost,
                        "model": model,
                    })
                    result_json.write_text(json.dumps(final_results, indent=4))

    # Sort CPVs by number
    def extract_cpv_number(cpv_string):
        match = re.search(r'cpv(\d+)', cpv_string)
        if match:
            return int(match.group(1))
        return 0
    
    # Group results by model
    results_by_model = {}
    for cpv, results in final_results.items():
        for result in results:
            model = result["model"]
            if model not in results_by_model:
                results_by_model[model] = []
            results_by_model[model].append((cpv, result))
 
    cpv_json = json.loads((BACKUP_FOLDER / "nginx_cpv_info.json").read_text())["cpvs"]
    GOOD = "✅"
    BAD = "❌"
    # Generate a table for each model
    for model, results in results_by_model.items():
        table = Table(title=f"Root Cause Analysis Results - {model}")
        table.add_column("CPV #", justify="right")
        table.add_column("Root Cause Found (Exact)", justify="center")
        table.add_column("Root Cause Found (Function)", justify="center")
        table.add_column("Root Cause Found (File)", justify="center")
        table.add_column("Root Cause Found (Any)", justify="center")
        table.add_column("Duration (s)", justify="right")
        table.add_column("Tools Used", justify="right")
        table.add_column("Cost ($)", justify="right")
        
        # Sort results by CPV number
        results.sort(key=lambda x: extract_cpv_number(x[0]))
        
        # Add rows to the table
        total_duration = 0
        total_cost = 0
        total_tools_used = 0
        total_exact_success = 0
        total_function_success = 0
        total_file_success = 0
        total_any_success = 0

        for cpv, result in results:
            root_cause_found = GOOD if result["root_cause"]["found_root_cause"] else BAD
            tools_count = len(result["tools_used"]) if result["tools_used"] else 0
            duration_formatted = f"{result['duration']:.2f}"
            cost_formatted = f"{result['cost']:.4f}" if result['cost'] else "N/A"
            total_duration += result["duration"]
            total_cost += result["cost"] if result["cost"] else 0
            total_tools_used += tools_count

            total_any_success += 1 if result["root_cause"]["found_root_cause"] else 0
            file_success = BAD
            function_success = BAD
            exact_success = BAD
            for root_cause in result["root_cause"]["root_cause_locations"]:
                for patch_info in cpv_json[cpv]["patch"]:
                    if patch_info["file"] in root_cause["signature"]:
                        file_success = GOOD
                        if patch_info["function"] in root_cause["signature"]:
                            function_success = GOOD
                            start = root_cause["start_line"]
                            end = root_cause["end_line"]
                            if patch_info["lines"][0] <= end and start <= patch_info["lines"][1]:
                                exact_success = GOOD
                                break
                if exact_success == GOOD:
                    break
            
            total_exact_success += 1 if exact_success == GOOD else 0
            total_function_success += 1 if function_success == GOOD else 0
            total_file_success += 1 if file_success == GOOD else 0

            table.add_row(
                cpv,
                exact_success,
                function_success,
                file_success,
                root_cause_found,
                duration_formatted,
                str(tools_count),
                cost_formatted,
            )
            

            new_result = result.copy()

            new_result["any_success"] = root_cause_found == GOOD
            new_result["exact_success"] = exact_success == GOOD
            new_result["function_success"] = function_success == GOOD
            new_result["file_success"] = file_success == GOOD

            idx = results_by_model[model].index((cpv, result))
            results_by_model[model][idx] = (cpv, new_result)

        table.add_section()
        table.add_row(
            "Average",
            "",
            "",
            "",
            "",
            f"{total_duration/len(results):.2f}",
            f"{total_tools_used/len(results):.2f}",
            f"{total_cost/len(results):.4f}",
        )

        table.add_section()
        table.add_row(
            "Total",
            f"{total_exact_success}/{len(results)}",
            f"{total_function_success}/{len(results)}",
            f"{total_file_success}/{len(results)}",
            f"{total_any_success}/{len(results)}",
            f"{total_duration:.2f}",
            str(total_tools_used),
            f"{total_cost:.4f}",
        )
        # Print the table for the current model
        console.print(table)
    
    # Calculate statistics for each model
    model_stats = {}
    for model, results in results_by_model.items():
        success_count = sum(1 for _, result in results if result["any_success"])
        total_count = len(results)
        success_rate = success_count / total_count if total_count > 0 else 0
        
        durations = [result["duration"] for _, result in results]
        avg_duration = statistics.mean(durations) if durations else 0
        
        tools_counts = [len(result["tools_used"]) if result["tools_used"] else 0 for _, result in results]
        avg_tools = statistics.mean(tools_counts) if tools_counts else 0
        
        costs = [result["cost"] for _, result in results if result["cost"] is not None]
        avg_cost = statistics.mean(costs) if costs else 0
        
        model_stats[model] = {
            "any_success_rate": success_rate,
            "exact_success_rate": sum(1 for _, result in results if result["exact_success"]) / total_count if total_count > 0 else 0,
            "function_success_rate": sum(1 for _, result in results if result["function_success"]) / total_count if total_count > 0 else 0,
            "file_success_rate": sum(1 for _, result in results if result["file_success"]) / total_count if total_count > 0 else 0,
            "avg_duration": avg_duration,
            "avg_tools": avg_tools,
            "avg_cost": avg_cost,
            "total_tests": total_count
        }
    
    # Create summary table
    summary_table = Table(title="Model Performance Summary")
    summary_table.add_column("Model", justify="left", style="cyan")
    summary_table.add_column("Exact Success Rate", justify="center", style="green")
    summary_table.add_column("Function Success Rate", justify="center", style="green")
    summary_table.add_column("File Success Rate", justify="center", style="green")
    summary_table.add_column("Any Success Rate", justify="center", style="green")
    summary_table.add_column("Avg. Duration (s)", justify="right", style="yellow")
    summary_table.add_column("Avg. Tools Used", justify="right", style="blue")
    summary_table.add_column("Avg. Cost ($)", justify="right", style="magenta")
    summary_table.add_column("Total Tests", justify="right", style="white")

    # Sort models alphabetically for the summary table
    for model in sorted(model_stats.keys()):
        stats = model_stats[model]
        
        # Determine color intensity for success rate
        any_success_color = "bright_green" if stats['any_success_rate'] > 0.75 else "green" if stats['any_success_rate'] > 0.5 else "red"
        exact_success_color = "bright_green" if stats['exact_success_rate'] > 0.75 else "green" if stats['exact_success_rate'] > 0.5 else "red"
        function_success_color = "bright_green" if stats['function_success_rate'] > 0.75 else "green" if stats['function_success_rate'] > 0.5 else "red"
        file_success_color = "bright_green" if stats['file_success_rate'] > 0.75 else "green" if stats['file_success_rate'] > 0.5 else "red"
        
        summary_table.add_row(
            model,
            f"[{exact_success_color}]{stats['exact_success_rate']:.2%}[/{exact_success_color}]",
            f"[{function_success_color}]{stats['function_success_rate']:.2%}[/{function_success_color}]",
            f"[{file_success_color}]{stats['file_success_rate']:.2%}[/{file_success_color}]",
            f"[{any_success_color}]{stats['any_success_rate']:.2%}[/{any_success_color}]",
            f"{stats['avg_duration']:.2f}",
            f"{stats['avg_tools']:.2f}",
            f"{stats['avg_cost']:.4f}",
            str(stats['total_tests'])
        )

    # Print the summary table
    console.print(summary_table)
    
    # Save final results to a JSON file
    
    console.save_text(BACKUP_FOLDER.parent / "console_output.log")

if __name__ == "__main__":
    args = parse_args()
    main(fresh=args.fresh, skip_run=args.skip_run, retry_models=args.retry_models, single_thread=args.single_thread)