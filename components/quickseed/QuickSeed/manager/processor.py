import json
import logging
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import List
import random

import yaml
import json
import hashlib
import time
from typing import Optional, Dict
from uuid import UUID
from QuickSeed.data import CallGraphNode
from QuickSeed.llm import SeedGenerator, SeedGeneratorTask, SarifReportAnalyzer, DiffAnalyzer, DiffAnalyzerTask
from QuickSeed.llm.agents import DiffAnalyzerOutput
from QuickSeed.parser import CallGraphParser, Neo4JBackend

from .scheduler import Scheduler
from QuickSeed.data.metadata import QuickSeedHarnessInfo
from QuickSeed.utils import extract_diff_function_infos
from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.function_resolver  import FunctionResolver
from shellphish_crs_utils.sarif_resolver import SarifLocation
_l = logging.getLogger(__name__)

VULN_TYPE_ORDER = ['CommandInjection', 'PathTraversal', 'ServerSideRequestForgery', 'Deserialization', \
                    'SqlInjection', 'XPathInjection', 'ReflectionCallInjection', 'ExpressionLanguage', 'LdapInjection', \
                    'NamingContextLookup', 'RegexInjection', 'ScriptEngineInjection']

class Processor:
    def __init__(
            self,
            call_graph_parser: Neo4JBackend,
            jazzer_json: Path,
            scheduler: Scheduler,
            available_models: List[str],
            harnesses: List[QuickSeedHarnessInfo],
            project_source: Path,
            function_resolver: FunctionResolver | None = None,
            commit_full_functions_dir: Path | None = None,
            sarif_report_result: List | None = None,
            codeswipe_funcs_ranking: List[str] | None = None,
            dynamic_call_graph: Optional[CallGraphParser] = None,
            ):
        self.call_graph_parser = call_graph_parser
        self.jazzer_json = jazzer_json
        self.scheduler = scheduler
        self.harnesses = harnesses
        self.available_models = available_models
        self.commit_full_functions_dir = commit_full_functions_dir
        self.project_source = project_source
        self.function_resolver = function_resolver
        self.sarif_result = sarif_report_result
        self.dynamic_call_graph = dynamic_call_graph
        # self.max_path_num = max_path_num
        self.codeswipe_funcs_ranking = codeswipe_funcs_ranking
        with open(self.jazzer_json, "r") as f:
            self.jazzer_sanitizer_description = json.load(f)


        self.harness_names = [harness_info.cp_harness_name for harness_info in self.harnesses]


    def _filter_path_by_diff_change(self, paths: list[list[CallGraphNode]]) -> list[list[CallGraphNode]]:
        # If no diff information available, return all paths
        if self.commit_full_functions_dir is None:
            _l.debug("No commit_full_functions_dir specified")
            return False, paths
        
        diff_function_infos = extract_diff_function_infos(self.commit_full_functions_dir)
        diff_function_names = [funcinfo.funcname for funcinfo in diff_function_infos]
        if len(diff_function_names) == 0:
            return False, paths
        path_function_map = {}
        for index, path in enumerate(paths):
            # Use frozenset directly - no need to sort
            path_functions = frozenset(node.function_name for node in path if node.function_name is not None)
            if path_functions not in path_function_map:
                path_function_map[path_functions] = []
            path_function_map[path_functions].append(index)

        selected_indices = set()
        for diff_function_name in diff_function_names:
            for path_functions, indices in path_function_map.items():
                if diff_function_name in path_functions:
                    selected_indices.update(indices)
        # Return only paths that contain changed functions
        filtered_paths = [paths[i] for i in selected_indices if i < len(paths)]
        _l.info(f"Filtered paths by diff change: {len(filtered_paths)} paths")
        if len(filtered_paths) == 0:
            _l.info("No paths found after filtering by diff change")
            return False, paths
        return True, filtered_paths
    

    def _get_paths_and_submit_tasks(self):
        importance_rate = {
            "CommandInjection": 0.5,
            "PathTraversal": 0.3,
        }
        if self.commit_full_functions_dir:
            diff_paths, overlapping_paths_source_to_sink, overlapping_paths_ending_at_sink = self.get_paths_in_diff_mode()
            updated = self.update_sinks_by_llm(diff_filtered_paths=overlapping_paths_ending_at_sink)
        else:
            updated = self.update_sinks_by_llm()

        ## Update sinks by llm and then update the paths in call graph parser
        vuln_types = []
        
        for vuln_type, is_updated in updated.items():
            if is_updated:
                vuln_types.append(vuln_type)

        if len(vuln_types) > 0:
            # if not all(value == [] for value in self.call_graph_parser.all_paths_ending_at_sinks.values()):
            # self.call_graph_parser.update_paths_ending_at_sink_node_ids(self.function_resolver, vuln_types)
            # else:
            self.call_graph_parser.update_all_paths_from_source_to_sink(vuln_types)

        if self.commit_full_functions_dir:
            # Since we might change 
            overlapping_paths_source_to_sink, overlapping_paths_ending_at_sinks = self.get_paths_overlapping_with_diff()
            self.rank_paths_and_submit_tasks_commit(diff_paths, overlapping_paths_source_to_sink, overlapping_paths_ending_at_sinks)
        else:
            paths = self.get_paths_in_full_mode(importance_rate)
            self._submit_seed_generator_tasks(paths)


    def _submit_seed_generator_tasks(self, paths: List[List[CallGraphNode]]):
        
        if isinstance(self.call_graph_parser, CallGraphParser):
            for path in paths:
                self.call_graph_parser.code_parse_for_nodes(path, self.function_resolver)
        count = 0

        _l.debug(f"We have {len(paths)} paths to generate seeds.")
        for path in paths:
            left_harnesses_to_try = list(range(len(self.harnesses)))
            if path[0].function_name == "fuzzerTestOneInput":
                harness_name = path[0].filepath.stem
                idx = self.harness_names.index(harness_name)
                harness_path = self.harnesses[idx].harness_source_path
                left_harnesses_to_try = [idx]
            # This is to avoid llm api rate limit
            model = self.available_models[count % len(self.available_models)]
            random.shuffle(left_harnesses_to_try)
            for harness_index in left_harnesses_to_try:
                harness = self.harnesses[harness_index]
                harness_name = self.harness_names[harness_index]
                harness_path = harness.harness_source_path
                seed_generator_task = SeedGeneratorTask(path, self.jazzer_sanitizer_description, self.project_source, model, harness_path, harness_name, left_harnesses_to_try=[harness_index])
                while not self.scheduler.shutdown_flag.is_set():
                    # Limit the size of scheduler queue to avoid the memory usage issue
                    if self.scheduler.get_queue_available_space() >= 10:            
                        self._submit_seed_generator_task(seed_generator_task, model)
                        break
                    else:
                        _l.debug("Scheduler queue is nearly full, waiting to submit seed generator task")
                        # Wait for a while before checking again
                        time.sleep(2)
            if self.scheduler.shutdown_flag.is_set():
                _l.debug("Scheduler shutdown flag is set, stopping seed generator task submission")
                break

                
            # harness = self.harnesses[left_harnesses_to_try[0]]
            # harness_name = self.harness_names[left_harnesses_to_try[0]]
            # harness_path = harness.harness_source_path
            # seed_generator_task = SeedGeneratorTask(path, self.jazzer_sanitizer_description,self.project_source, model, harness_path, harness_name, left_harnesses_to_try=left_harnesses_to_try)
            # self._submit_seed_generator_task(seed_generator_task, model)
            count += 1


    def _submit_seed_generator_task(self, task: SeedGeneratorTask, model: str):
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        fallback_seed_gen_scripts_dir = Path(tempfile.mkdtemp())
        harness_benign_seeds_dir, _ = self.get_harness_benign_crash_seeds_dir(task.harness_name)
        seed_generator_processor = SeedGenerator(
                agent_plan,
                self.call_graph_parser.cp_root,
                self.call_graph_parser.func_indexer_path,
                self.call_graph_parser.function_json_dir,
                model,
                benign_seeds_dir=harness_benign_seeds_dir,
                fall_back_python_script=fallback_seed_gen_scripts_dir,
            )
        self.scheduler.submit_task(seed_generator_processor, task)

    def _real_harness_filepath(self, harness_filepath: Path) -> Path:

        if harness_filepath.exists():
            return harness_filepath
        else:

            src_index = harness_filepath.parts.index('src')
            relative_path = Path(*harness_filepath.parts[src_index:])

            prefix = self.call_graph_parser.cp_root
            harness_filepath = prefix / relative_path

            _l.debug(f"The adjusted harness path is {harness_filepath}")
            return harness_filepath

    def find_harness_name(self, node: CallGraphNode) -> str:
        filepath = node.filepath
        project_yaml = self.call_graph_parser.cp_root / "project.yaml"
        with open(project_yaml, "r") as f:
            project = yaml.safe_load(f)
        harnesses = project.get("harnesses")
        _l.debug(f"harnesses is {harnesses}")
        for harness_id, harness in harnesses.items():
            _l.debug(f"harness in {harness}")
            _l.debug(f"self.harness_filepath is {filepath}")
            if str(filepath).endswith(harness.get("source")):
                return harness.get("name")

    def get_source_code(self, node_path: List[CallGraphNode]):
        source_code = ""
        count = 1
        for node in node_path:
            source_code += f"{count}. {node.function_name}\n"
            count += 1
            if node.function_code is not None:
                source_code += f"{node.function_code}\n"
        return source_code

    def update_sinks_by_llm(self, diff_filtered_paths: Optional[Dict] = None):
        updated = self.call_graph_parser.find_new_sinks_by_llm(chosen_paths=diff_filtered_paths)
        self.call_graph_parser.update_graph()
        self.call_graph_parser._check_missing_nodes()
        return updated

    def get_harness_benign_crash_seeds_dir(self, harness_name: str):
        harness_index = self.harness_names.index(harness_name)
        harness = self.harnesses[harness_index]
        harness_benign_seeds_dir = harness.harness_benign_dir
        harness_crash_seeds_dir = harness.harness_crash_dir
        return harness_benign_seeds_dir, harness_crash_seeds_dir

    def find_call_chains_ending_at_locations(self, locations: List[SarifLocation])-> List[List[str]]:
        paths = []
        for location in locations:
            full_name = self.get_full_method_name_from_sarif_location(location)
            for vuln, sink_ids in self.call_graph_parser.sink_node_ids_by_type.items():
                for sink_id in sink_ids:                   
                    if self.call_graph_parser.nodes[sink_id].qualified_name in full_name:
                        new_paths = self.call_graph_parser.get_paths_of_length_ending_at(sink_id, max_length=10)
                        paths.extend([path for path in new_paths if path not in paths])
        paths = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(paths)
        name_paths = []
        name_paths_starting_with_harness = []
        for path in paths:
            name_path = [node.qualified_name for node in path]
            name_paths.append(name_path)
            if "fuzzerTestOneInput" in name_path[0]:
                name_paths_starting_with_harness.append(name_path)
        if len(name_paths_starting_with_harness) > 0:
            return name_paths_starting_with_harness
        else:
            return name_paths
        
    def get_full_method_name_from_sarif_location(self, sarif_location: SarifLocation)->str:

        loc_id = sarif_location.keyindex
        return self.function_resolver.get(loc_id).full_funcname   
    
    def get_full_method_name_from_yajta_sig(self, yajta_sig: str) -> str:
        # This is a temporary solution to get the full method name from yajta signature
        return yajta_sig.split("(")[0]
    
    def _submit_sarif_analyzer_task(self, 
                                    sarif_analyzer_task, 
                                    plan_name, 
                                    sarif_output_object, 
                                    count, 
                                    harness,
                                    covered_functions=None, 
                                    previous_script=None):
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        sarif_report_analyzer = SarifReportAnalyzer(
            agent_plan,
            self.call_graph_parser.cp_root,
            self.call_graph_parser.func_indexer_path,
            self.call_graph_parser.function_json_dir,
            model=self.available_models[count%len(self.available_models)],
            benign_seeds_dir=harness.harness_benign_dir,
            fall_back_python_script=Path(tempfile.mkdtemp()),
            previous_script=previous_script, 
            covered_functions = covered_functions,
            function_resolver=self.function_resolver,
            oss_fuzz_build=self.call_graph_parser.oss_fuzz_build,
        )
        if previous_script or covered_functions:
            self.scheduler.submit_task_prioritize(sarif_report_analyzer, sarif_analyzer_task, plan_name, sarif_output_object)
        else:
            self.scheduler.submit_task(sarif_report_analyzer, sarif_analyzer_task, plan_name, sarif_output_object)

    def get_harness(self, harness_name: str):
        harness_ind = self.harness_names.index(harness_name)
        harness = self.harnesses[harness_ind]
        return harness
    
    def rotate_model(self, model: str)-> str:
        ind = self.available_models.index(model)
        count = (ind + 1) % len(self.available_models)
        return count

    def add_if_is_not_triaged(self, file: Path, md5_sigs: List[str]):
        with open(file, "rb") as f:
            md5name = hashlib.md5(f.read()).hexdigest() 
        if md5name in md5_sigs:
            return True
        md5_sigs.append(md5name)
        return False

    def get_diff_paths(self):
        if self.call_graph_parser.all_paths_ending_at_sinks['Diff']:
            paths = self.call_graph_parser.all_paths_ending_at_sinks["Diff"]
        else:
            paths = self.call_graph_parser.all_paths_from_source_to_sink["Diff"]
        paths = self.call_graph_parser.filter_pass(paths, self.function_resolver)
        # paths = self.call_graph_parser.filter_paths_by_sublist(paths)
        node_paths = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(paths)
        return node_paths
    
    def get_paths_overlapping_with_diff(self):
        # if not all(value == [] for value in self.call_graph_parser.all_paths_ending_at_sinks.values()):
        all_paths_from_source_to_sink = self.call_graph_parser.all_paths_from_source_to_sink.copy()
        all_paths_ending_at_nodes = self.call_graph_parser.all_paths_ending_at_sinks_when_no_path_from_source.copy()

        filtered_all_paths_by_diff_change = self.get_diff_filter_path_dict(all_paths_from_source_to_sink)
        filtered_all_paths_by_diff_change_ending_at_sinks = self.get_diff_filter_path_dict(all_paths_ending_at_nodes)
        return filtered_all_paths_by_diff_change, filtered_all_paths_by_diff_change_ending_at_sinks
    
    def get_paths_in_full_mode(self, importance_rate):
        most_important_paths = [path for paths in self.call_graph_parser.paths_filtered_by_dumb_data_flow.values() for path in paths]
        vuln_types = self.call_graph_parser.sink_node_ids_by_type.keys()
        assert "Diff" not in vuln_types
        paths = []
        path_dict = {}

        for sink_type in vuln_types:
            node_paths = self.call_graph_parser.path_search_hierarchy(vuln_type=sink_type, function_resolver=self.function_resolver)

            paths_from_source_to_sink = self.call_graph_parser.all_paths_from_source_to_sink.get(sink_type)
            node_paths.extend([p for p in paths_from_source_to_sink if p not in node_paths])
            path_dict[sink_type] = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(node_paths)


        paths = self.call_graph_parser.sort_paths(path_dict, importance_rate, threshold=self.max_path_num, vuln_type_order=VULN_TYPE_ORDER)
        _l.info(f"Call graph parser get {len(paths)} paths to seed generator tasks")

        if len(most_important_paths) > 0:
            paths = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(most_important_paths) + paths

        paths = self.reorder_paths_by_codeswipe_ranking_round_robin(paths)

        # if len(paths) > self.max_path_num:
        #     paths = paths[:self.max_path_num]
        return paths

    def get_paths_in_diff_mode(self):
        
        diff_paths = self.get_diff_paths()
        overlapping_paths_source_to_sink, overlapping_paths_ending_at_sink = self.get_paths_overlapping_with_diff()
        return diff_paths, overlapping_paths_source_to_sink, overlapping_paths_ending_at_sink
    
    def rank_paths_and_submit_tasks_commit(self, diff_paths, overlapping_paths_source_to_sink, overlapping_paths_ending_at_sink):
        paths_starting_with_source = []
        paths_not_starting_with_source = []
        paths_starting_with_source = self.order_paths_from_dict(overlapping_paths_source_to_sink, VULN_TYPE_ORDER)
        paths_not_starting_with_source = self.order_paths_from_dict(overlapping_paths_ending_at_sink, VULN_TYPE_ORDER)

        uuid_overlapping_path_list = paths_starting_with_source + paths_not_starting_with_source
        uuid_diff_path_list = [[node.id for node in path] for path in diff_paths]
        sorted_paths = uuid_overlapping_path_list + [path for path in uuid_diff_path_list if path not in uuid_overlapping_path_list]
        sorted_node_paths = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(sorted_paths)
        inter_len = len(uuid_overlapping_path_list)
        sorted_node_paths = self.reorder_paths_by_codeswipe_ranking_round_robin(sorted_node_paths)
        # if inter_len >= self.max_path_num:
        #     self._submit_seed_generator_tasks(sorted_node_paths[:self.max_path_num])
        # else:
        self._submit_seed_generator_tasks(sorted_node_paths[:inter_len])
        self._submit_diff_analyzer_tasks(sorted_node_paths[inter_len:], len(sorted_node_paths)-inter_len)
        # self._submit_diff_analyzer_tasks(sorted_node_paths[inter_len:inter_len+1], 1)
        return sorted_node_paths
    
    def _submit_diff_analyzer_tasks(self, paths: List[List[CallGraphNode]], max_num):
        # with open(self.jazzer_json, "r") as f:
        #     jazzer_sanitizer_description = json.load(f)
        for path in paths:
            self.call_graph_parser.code_parse_for_nodes(path, self.function_resolver, enable_codeql=True)
        count = 0
        grouped_paths = self.group_paths_by_last_node(paths)

        # from remote_pdb import RemotePdb; RemotePdb('0.0.0.0', 4444).set_trace()
        for function_id, paths in grouped_paths.items():
            if count > max_num:
                break
            if not paths[0][-1].function_code:
                _l.warning(f"Commit function does not have source code of it. Skiping this path ...")
                continue
            paths = self.call_graph_parser.filter_path_by_harness(paths)

            # We already using polycalls here, if a function cannot be reached from harness. We do not care
            if len(paths) == 0:
                continue
            call_chains = [[node.qualified_name for node in path] for path in paths]
            functions = []
            function_names = []
            harness_indices = []
            for path in paths:
                if path[0].function_name == "fuzzerTestOneInput":
                    harness_name = path[0].filepath.stem
                    harness_index = self.harness_names.index(harness_name)
                    if harness_index not in harness_indices:
                        harness_indices.append(harness_index)
                for node in path:
                    if node.function_name not in function_names:
                        function_names.append(node.function_name)
                        if node.function_code is not None:
                            functions.append(node.function_code)

            # Limit the function number to 10 to avoid super long context
            if len(functions) >= 10:
                functions = functions[:10]
            if len(harness_indices) == 0:
                harness_indices = list(range(len(self.harnesses)))
            for harness_ind in harness_indices:
                harness = self.harnesses[harness_ind]
                diff_analyzer_task = DiffAnalyzerTask(
                    self.jazzer_sanitizer_description,
                    model = self.available_models[count%len(self.available_models)],
                    harness_filepath = self.harnesses[harness_ind].harness_source_path,
                    harness_name = self.harnesses[harness_ind].cp_harness_name,
                    project_source = self.project_source,
                    node_path = path,
                    attempt=0,
                    call_chains = call_chains,
                    commit_function = path[-1].function_code,
                    functions_on_call_chains=functions
                )
                self._submit_diff_analyzer_task(diff_analyzer_task, "diff_analyzer_plans.yaml", DiffAnalyzerOutput, count, harness)
            count += 1
    
    def group_paths_by_last_node(self, paths: List[List[CallGraphNode]]) -> dict[UUID, List[List[CallGraphNode]]]:
        grouped_paths = defaultdict(list)
        for path in paths:
            last_node = path[-1]
            grouped_paths[last_node.id].append(path)
        return grouped_paths
    
    def reorder_paths_by_codeswipe_ranking_round_robin(self, paths: List[List[CallGraphNode]], sink_function_num: int=20, round_robin_num: int=3) -> List[List[CallGraphNode]]:
        """
        Group paths by if there is the node full name in the path
        We conidier the first sink_function_num functions in the codeswipe_funcs_ranking
        And then we reorder the paths by round robin rotate by round_robin_num
        Choose round_robin_num paths for each function in codeswipe_funcs_ranking and go to the next functions
        After we finish the first sink_function_num functions, we add the next batch of sink_function_num functions the same way
        """
        if not self.codeswipe_funcs_ranking:
            return paths
        node_paths = paths.copy()
        reordered_paths = []
        grouped_paths = self.group_by_including_nodes_in_codeswipe(node_paths)

        batch_start = 0
        batch_end = min(sink_function_num, len(self.codeswipe_funcs_ranking))
        while batch_start < len(self.codeswipe_funcs_ranking):
            current_sink_functions = self.codeswipe_funcs_ranking[batch_start:batch_end]
            while len(current_sink_functions) > 0:

                to_be_deleted = []
                for i, full_name in enumerate(current_sink_functions):
                    if full_name not in grouped_paths:
                        to_be_deleted.append(full_name)  # Mark as processed
                        continue
                    paths_for_function = grouped_paths[full_name]
                    if len(paths_for_function) == 0:
                        to_be_deleted.append(full_name)  # Mark as processed
                        continue
                    # We take round_robin_num paths for each
                    if len(paths_for_function) > round_robin_num:
                        reordered_paths.extend(paths_for_function[:round_robin_num])
                        grouped_paths[full_name] = paths_for_function[round_robin_num:]
                    else:
                        reordered_paths.extend(paths_for_function)
                        grouped_paths[full_name] = []
                        to_be_deleted.append(full_name)  # Mark as processed
                        # Mark as processed
                # Convert to set for O(1) lookup instead of O(n)
                to_be_deleted_set = set(to_be_deleted)
                new_current_sink_functions = [func for func in current_sink_functions if func not in to_be_deleted_set]
                current_sink_functions = new_current_sink_functions
            batch_start += sink_function_num
            batch_end = min(batch_start + sink_function_num, len(self.codeswipe_funcs_ranking))
        reordered_paths.extend(grouped_paths["Other"])  # Add remaining paths not in codeswipe ranking
        return reordered_paths
            
    
    def group_by_including_nodes_in_codeswipe(self, paths: List[List[CallGraphNode]]) -> Dict[str, List[List[CallGraphNode]]]:
        grouped_paths = defaultdict(list)
        
        # Create mapping from function name to paths containing it
        function_to_paths = defaultdict(list)
        unassigned_paths = set(range(len(paths)))
        
        for path_idx, path in enumerate(paths):
            for node in path:
                func_name = node.qualified_name
                if func_name in self.codeswipe_funcs_ranking:
                    function_to_paths[func_name].append(path_idx)
                    break
        
        # Assign paths based on ranking priority
        for full_name in self.codeswipe_funcs_ranking:
            if full_name in function_to_paths:
                for path_idx in function_to_paths[full_name]:
                    if path_idx in unassigned_paths:
                        grouped_paths[full_name].append(paths[path_idx])
                        unassigned_paths.remove(path_idx)
        
        # Add remaining unassigned paths
        if unassigned_paths:
            grouped_paths["Other"] = [paths[i] for i in unassigned_paths]
        
        return grouped_paths
    
    def order_paths_from_dict(self,paths_dict: Dict[str, List[List[CallGraphNode]]], order: List[str]) -> List[List[UUID]]:
        '''
        Order the paths in paths_dict according to the order list
        '''
        ordered_paths = []
        for key in order:
            if key in paths_dict:
                paths = paths_dict[key]
                for path in paths:
                    ordered_paths.append([node.id for node in path])           
        return ordered_paths

    def get_diff_filter_path_dict(self, path_dict: Dict[str, List[List[UUID]]])-> Dict[str, List[List[CallGraphNode]]]:
        
        diff_filtered_paths = defaultdict(list)
        for vuln_type, paths in path_dict.items():
            if vuln_type == "Diff":
                continue
            paths = self.call_graph_parser.filter_pass(paths, self.function_resolver)
            # paths = self.call_graph_parser.filter_paths_by_sublist(paths)
            node_paths = self.call_graph_parser.paths_mapping_from_UUID_to_CallGraphNode(paths)
            success, filtered_paths = self._filter_path_by_diff_change(node_paths)
            if success:
                diff_filtered_paths[vuln_type] = filtered_paths
        return diff_filtered_paths
    
    def _submit_diff_analyzer_task(self, task: DiffAnalyzerTask, plan_name, output_object, count, harness, 
                                   covered_functions: Optional[str] = None, previous_script: Optional[str] = None):
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        fall_back_seed_gen_scripts_dir = Path(tempfile.mkdtemp())
        diff_analyzer = DiffAnalyzer(
            agent_plan,
            self.call_graph_parser.cp_root,
            self.call_graph_parser.func_indexer_path,
            self.call_graph_parser.function_json_dir,
            model=self.available_models[count%len(self.available_models)],
            benign_seeds_dir=harness.harness_benign_dir,
            fall_back_python_script=fall_back_seed_gen_scripts_dir,
            previous_script=previous_script,
            covered_functions=covered_functions,
        )

        self.scheduler.submit_task(diff_analyzer, task, plan_name, output_object)
                
                                                            