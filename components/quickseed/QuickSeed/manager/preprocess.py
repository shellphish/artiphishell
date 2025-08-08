
from typing import List
import tempfile
from pathlib import Path
from shellphish_crs_utils.function_resolver import FunctionResolver
from QuickSeed.data.metadata import QuickSeedHarnessInfo
from QuickSeed.data.graph import CallGraphNode
from QuickSeed.parser import Neo4JBackend, CallGraphParser
from QuickSeed.llm import WarmUpTask, WarmUp
from QuickSeed.utils import convert_function_resolver_identifier_to_call_graph_node
from .scheduler import Scheduler
from  .processor import Processor
import logging
_l = logging.getLogger(__name__)

class PreProcessor(Processor):
    def __init__(
            self,
            scheduler: Scheduler,
            call_graph_parser: Neo4JBackend,
            jazzer_json,
            harnesses: List[QuickSeedHarnessInfo],
            available_models: list,
            project_source: Path,
            function_resolver: FunctionResolver,
            codeswipe_funcs_ranking_names: List[str],
            dynamic_call_graph: CallGraphParser
    ):
        super().__init__(call_graph_parser=call_graph_parser,
                         jazzer_json=jazzer_json,
                         scheduler=scheduler,
                         available_models=available_models,
                         harnesses=harnesses,
                         project_source=project_source,
                         function_resolver=function_resolver,
                         codeswipe_funcs_ranking=codeswipe_funcs_ranking_names,
                         dynamic_call_graph=dynamic_call_graph)

    def submit_tasks_to_scheduler(self):
        return self._operate()
    
    def _operate(self):
        self._submit_warm_up_tasks()
        
    
    def _submit_warm_up_tasks(self):
        _l.debug("Submitting warm up tasks.")
        # This is to submit tasks to invoke warm up agent
        count = 0
        for harness in self.harnesses:
            fall_back_python_script = Path(tempfile.mkdtemp())
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
        # Submit termination task after warm up tasks so that posprocessor exit after process all of the warm up tasks
        # self.scheduler.submit_termination_task()

    def submit_seed_generator_tasks_while_waiting_for_warm_up(self, selected_paths: List[List[CallGraphNode]]):
        _l.debug("Submitting seed generator tasks while waiting for warm up.")
        self._submit_seed_generator_tasks(selected_paths)
