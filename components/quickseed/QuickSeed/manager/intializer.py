import os
import logging
import tempfile
from pathlib import Path
from typing import List, Optional
from uuid import UUID
from collections import defaultdict
import random

import yaml
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.sarif_resolver import SarifCodeFlow, SarifResult
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata
from QuickSeed.data import CallGraphNode
from QuickSeed.llm import ReflectionAnalyzer, ReflectionAnalyzerTask, SarifReportAnalyzerTask, WarmUp, WarmUpTask
from QuickSeed.llm.agents import SarifAnalyzerOutput
from QuickSeed.parser import Neo4JBackend, CallGraphParser
from QuickSeed.parser import path_rank
from .processor import Processor
from .scheduler import Scheduler

from QuickSeed.data.metadata import QuickSeedHarnessInfo
from QuickSeed.utils import find_absolute_path2
# from .task import SeedGeneratorTask, ReflectionAnalyzerTask

_l = logging.getLogger(__name__)


class Initializer(Processor):
    """
    This Initializer is called at the beginning of the seed generation process.
    It takes initial call graph and produce two types of tasks:
    1. SeedGeneratorTask for those complete paths from source to sink
    2. ReflectionAnalyzerTask for those paths that contain reflection calls
    """

    def __init__(
            self,
            scheduler: Scheduler,
            call_graph_parser: Neo4JBackend,
            reflection_parser,
            jazzer_json,
            harnesses: List[QuickSeedHarnessInfo],
            available_models: list,
            project_source: Path,
            function_resolver: FunctionResolver,
            reflection_output_dir=None,
            commit_full_functions_dir: Path | None =None,
            sarif_report_result: SarifResult | None = None,
            codeswipe_funcs_raking: List[str] | None = None,
            dynamic_call_graph: Optional[CallGraphParser] = None,
            sarif_meta: Optional[SARIFMetadata] = None,
    ):
        super().__init__(call_graph_parser, jazzer_json, scheduler, available_models, harnesses, project_source, 
                         function_resolver, commit_full_functions_dir, sarif_report_result, codeswipe_funcs_raking,
                         dynamic_call_graph)

        self.reflection_parser = reflection_parser
        self.query_paths = []
        self.reflection_output_dir = reflection_output_dir
        self.sarif_meta = sarif_meta

        

    def submit_tasks_to_scheduler(self, remaining_neo4j_raw_paths: Optional[List[List[List[CallGraphNode]]]] = None):
        return self._operate(remaining_neo4j_raw_paths)

    def _operate(self, remaining_neo4j_raw_paths: List[List[List[CallGraphNode]]] | None):
        if self.sarif_result:   
            sinks = self.call_graph_parser.get_sinks()
            paths = []
            for sink in sinks:
                paths_to_sink = self.call_graph_parser.get_paths_for_sink(sink, limit=10)
                paths.extend(paths_to_sink)

            # self._submit_seed_generator_tasks(node_paths)
            self._submit_sarif_report_tasks(paths)
            return
        # if not remaining_neo4j_raw_paths:
        #     remaining_neo4j_raw_paths = []
        #     sinks = self.call_graph_parser.get_sinks()
        #     for i, sink in enumerate(sinks):
        #         paths_to_sink = self.call_graph_parser.get_paths_for_sink(sink, limit=3)
        #         if len(paths_to_sink) > 3:
        #             paths_to_sink = self.call_graph_parser.paths_with_common_nodes(paths_to_sink)
        #         remaining_neo4j_raw_paths.append(paths_to_sink)
        #     ranked_paths = path_rank(
        #         remaining_neo4j_raw_paths, batch_size=5, round_robin_size=3)
        #     expanded_paths = self.call_graph_parser.expand_paths_with_codeql_query(ranked_paths)
        #     self._submit_seed_generator_tasks(expanded_paths)
        #     return
        # ########################################
        all_dynamic_paths = self.dynamic_call_graph.get_dynamic_paths_from_sources_to_sinks()
        # Clear the dynamic call graph graphs because we won't use it anymore.
        # Hopefully this will solve the OOM killed issue
        self.dynamic_call_graph.clear_graphs()
        sinks = self.call_graph_parser.get_sinks()
        paths = []

        _l.debug(f"There are {len(sinks)} sinks in the call graph. Getting the paths")
        assert len(sinks) == len(remaining_neo4j_raw_paths), \
                f"Number of sinks {len(sinks)} does not match number of remaining paths {len(remaining_neo4j_raw_paths)}"
        for i, sink in enumerate(sinks):
            # paths_to_sink = self.call_graph_parser.get_paths_for_sink(sink, limit=3)
            paths_to_sink = remaining_neo4j_raw_paths[i]
            if len(paths_to_sink) == 0:
                continue
            dynamic_paths = all_dynamic_paths[i]
            if len(dynamic_paths) > 0:
                paths_to_sink = self.call_graph_parser.filter_paths_by_dynamic_call_paths(paths_to_sink, dynamic_paths)
            paths.append(paths_to_sink)
        # Do the rerank first
        paths = self.call_graph_parser.rerank_paths_by_filtered_paths(paths)
        # If for any sink to the paths to it is more than 5, we will filter the paths with common nodes
        for i, paths_to_sink in enumerate(paths):
            if len(paths_to_sink) > 5:
                modified_paths = self.call_graph_parser.paths_with_common_nodes(paths_to_sink, threshold=5)
                if len(modified_paths) > 5:
                    random.shuffle(modified_paths)
                    modified_paths = modified_paths[:5]
                paths[i] = modified_paths
        ranked_paths = path_rank(
            paths, batch_size=10, round_robin_size=3)
        expanded_paths = self.call_graph_parser.expand_paths_with_codeql_query(ranked_paths)
        self._submit_seed_generator_tasks(expanded_paths)
        # else:
        #     self._get_paths_and_submit_tasks()

    def _submit_reflection_analyzer_tasks(self, max_num_tasks=1):
        _l.debug("Submitting reflection analyzer tasks.")

        for i in self.call_graph_parser.source_node_ids:
            paths = self.call_graph_parser.all_paths_start_with_source(i)
            paths = self.filter_paths_with_reflection(paths)
            # Filter out paths by focus repo
            paths = self.call_graph_parser.filter_paths_by_focus_repo(paths, self.function_resolver)
   
            node_paths = []
            if len(paths) > max_num_tasks:
                paths = paths[:max_num_tasks]
            for path in paths:
                node_path = [self.call_graph_parser.nodes[node_id] for node_id in path]
                self.call_graph_parser.code_parse_for_nodes(node_path, self.function_resolver)
                node_paths.append(node_path)
            # Filter out paths by diff change
            _, node_paths = self._filter_path_by_diff_change(node_paths)
            count = 0
            self.query_paths = [path for path in paths if path not in self.query_paths]
            for node_path in node_paths:
                source_node = self.call_graph_parser.nodes[path[0]]
                # We assume this how harness name is generated in configuration splitter, should check later
                harness_name = str(source_node.filepath.stem)
                # node_path = [self.call_graph_parser.nodes[node_id] for node_id in path]
                seed_output_dir = self.reflection_output_dir / harness_name
                seed_output_dir.mkdir(parents=True, exist_ok=True)
                reflection_analyzer_task = ReflectionAnalyzerTask(node_path, harness_name,
                                                                  self.call_graph_parser.func_indexer_path,
                                                                  self.call_graph_parser.cp_root, seed_output_dir,
                                                                  self.project_source,
                                                                  self.query_paths)
                _l.debug(f"Generating seeds to trigger reflection for {node_path}")
                agent_plan = tempfile.NamedTemporaryFile(delete=False).name
                fallback_seed_gen_scripts_dir = Path(tempfile.mkdtemp())
                model = self.available_models[count % len(self.available_models)]
                harness_benign_seeds_dir, _ = self.get_harness_benign_crash_seeds_dir(harness_name)
                reflection_analyzer_processor = ReflectionAnalyzer(
                    agent_plan,
                    self.call_graph_parser.cp_root,
                    self.call_graph_parser.func_indexer_path,
                    self.call_graph_parser.function_json_dir,
                    model,                    
                    seed_output_dir,
                    benign_seeds_dir=harness_benign_seeds_dir,
                    fall_back_python_script=fallback_seed_gen_scripts_dir ,
                )

                self.scheduler.submit_task(reflection_analyzer_processor, reflection_analyzer_task)
                count += 1

    def filter_paths_with_reflection(self, paths: List[List[UUID]]) -> List[List[UUID]]:
        filtered_paths = []
        for path in paths:
            for i, node_id in enumerate(path):
                node = self.call_graph_parser.nodes[node_id]
                if node.function_name in self.reflection_parser.methods_invoking_reflection:
                    if path[:i + 1] not in filtered_paths:
                        filtered_paths.append(path[:i + 1])
                    break
        return filtered_paths


    def _submit_sarif_report_tasks(self, paths: List[List[CallGraphNode]]):
        _l.debug("Submitting sarif report tasks.")
        # This is to submit tasks to invoke reflection analyzer agent
        count = 0
        for path in paths:
            left_harnesses_to_try = set()
            if path[0].filepath.name in self.call_graph_parser.harnesses_filename:
                harness_name = path[0].filepath.stem
                left_harnesses_to_try.add(self.harness_names.index(harness_name))
            left_harnesses_to_try = list(left_harnesses_to_try) if left_harnesses_to_try else list(range(len(self.harnesses)))
            # if "fuzzerTestOneInput" in name_paths[0][0]:
            #     harness_name = paths[0][0].split(".")[-2]
            #     left_harnesses_to_try = [self.harness_names.index(harness_name)]
            random.shuffle(left_harnesses_to_try)
            data_flows_codes = []
            ## EXPERIMENTAL
            location = self.sarif_result.locations[-1]
            function_code = self.function_resolver.get_code(location.keyindex)[-1]
            ##########
            data_flows_codes = self.get_sarif_report_code_flow_codes(self.sarif_result.codeflows)
            for harness_index in left_harnesses_to_try:
                harness = self.harnesses[harness_index]
                sarif_report_analyzer_task = SarifReportAnalyzerTask(
                    sarif_report_result=self.sarif_result,
                    jazzer_sanitizer_description=self.jazzer_sanitizer_description,
                    model=self.available_models[count % len(self.available_models)],
                    harness_filepath=Path(harness.harness_source_path),
                    harness_name=harness.cp_harness_name,
                    project_source=self.project_source,
                    attempt=0,
                    left_harnesses_to_try=list(range(len(self.harnesses))),
                    function_code = function_code,
                    data_flow_codes=data_flows_codes,
                    node_path=path,
                    sarif_meta=self.sarif_meta,
                )
                self._submit_sarif_analyzer_task(sarif_report_analyzer_task, "sarif_report_explore_plans.yaml", SarifAnalyzerOutput, count, harness)
                count += 1

        
    
    def get_sarif_report_code_flow_codes(self, codeflows: SarifCodeFlow):
        data_flows_codes = []
        for data_flow in codeflows:
            data_flow_code = []
            locations = data_flow.locations
            for location in locations:
                code_region = location.region
                code_file = location.file
                startline = code_region.get("startLine")
                startcolumn = code_region.get("startColumn")
                endcolumn = code_region.get("endColumn")
                if code_region.get("endLine"):
                    endline = code_region.get("endLine")
                else:
                    endline = startline
                filepath = find_absolute_path2(self.project_source, code_file)
                with open(filepath, "r") as f:
                    lines = f.readlines()
                    code_lines = lines[startline - 1:endline]
                    code_lines[0] = code_lines[0][startcolumn - 1:]
                    code_lines[-1] = code_lines[-1][:endcolumn]
                    code = "".join(code_lines)
                data_flow_code.append(code)
            data_flows_codes.append(data_flow_code)
        return data_flows_codes

    def backup_paths_from_graph(self):
        """
        This function is to backup the paths from the call graph
        :return:
        """
        threshold = 10
        # Backup paths ending at sinks
        original_all_paths_ending_at_sinks = self.call_graph_parser.all_paths_ending_at_sinks.copy()
        self.call_graph_parser.get_paths_ending_at_sink_node_ids(self.function_resolver, threshold=threshold)
        backup_file = os.getenv("QUICKSEED_PATH_BACKUP_REPORT")
        # vuln_node_path = defaultdict(list)
        vuln_node_path = {
            "max_length": threshold,
            "paths_ending_at_sinks": {},
            "paths_from_sourcs_to_sinks": {}
    }    
        for key, paths in self.call_graph_parser.all_paths_ending_at_sinks.items():
            for path in paths:
                node_path = [self.call_graph_parser.nodes[node_id].qualified_name for node_id in path]
                if key not in vuln_node_path["paths_ending_at_sinks"]:
                    vuln_node_path["paths_ending_at_sinks"][key] = []
                vuln_node_path["paths_ending_at_sinks"][key].append(node_path)
        # After backup, we need to restore the original all_paths_ending_at_sinks
        self.call_graph_parser.all_paths_ending_at_sinks = original_all_paths_ending_at_sinks

        # Backup paths from source to sinks
        # original_all_paths_from_source_to_sinks = self.call_graph_parser.all_paths_from_source_to_sink.copy()
        # original_all_paths_ending_at_sinks_when_no_path_from_source = self.call_graph_parser.all_paths_ending_at_sinks_when_no_path_from_source.copy()
        # self.call_graph_parser.get_all_paths_from_source_to_sink(max_length=threshold)
        # We already call get_all_paths_from_source_to_sink in the constructor of CallGraphParser
        for key, paths in self.call_graph_parser.all_paths_from_source_to_sink.items():
            for path in paths:
                node_path = [self.call_graph_parser.nodes[node_id].qualified_name for node_id in path]
                if key not in vuln_node_path["paths_from_sourcs_to_sinks"]:
                    vuln_node_path["paths_from_sourcs_to_sinks"][key] = []
                vuln_node_path["paths_from_sourcs_to_sinks"][key].append(node_path)
        # After backup, we need to restore the original all_paths_from_source_to_sink
        # self.call_graph_parser.all_paths_from_source_to_sink = original_all_paths_from_source_to_sinks
        # self.call_graph_parser.all_paths_ending_at_sinks_when_no_path_from_source = original_all_paths_ending_at_sinks_when_no_path_from_source
        with open(backup_file, "w") as f:
            yaml.dump(vuln_node_path, f)

    def _submit_warm_up_tasks(self):
        _l.debug("Submitting warm up tasks.")
        # This is to submit tasks to invoke warm up agent
        count = 0
        for harness in self.harnesses: 
            fall_back_python_script=Path(tempfile.mkdtemp())
            benign_seeds_dir, _ = self.get_harness_benign_crash_seeds_dir(harness.cp_harness_name)
            harness_name = harness.cp_harness_name
            harness_source_path = Path(harness.harness_source_path)
            agent_plan = tempfile.NamedTemporaryFile(delete=False).name
            warm_up_task = WarmUpTask(
                harness_name=harness_name,
                harness_filepath=harness_source_path,
                model=self.available_models[count % len(self.available_models)],
                project_source=self.project_source,
            )
            warm_up_agent = WarmUp(
                model=self.available_models[count % len(self.available_models)],
                agent_plan=agent_plan,
                cp_root=self.call_graph_parser.cp_root,
                function_indices=self.call_graph_parser.func_indexer_path,
                function_json_dir=self.call_graph_parser.function_json_dir,
                fall_back_python_script=fall_back_python_script,
                oss_fuzz_build=self.call_graph_parser.oss_fuzz_build,
                function_resolver=self.function_resolver,
                benign_seeds_dir=benign_seeds_dir,
            )
            self.scheduler.submit_task(warm_up_agent, warm_up_task)
            count += 1