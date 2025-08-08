from pathlib import Path
from typing import List, Optional, Dict
from uuid import UUID

from shellphish_crs_utils.sarif_resolver import SarifResult
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata
from QuickSeed.data import TriageCoverage, CallGraphNode, CallGraphEdge


class BaseTask:
    pass


class SeedGeneratorTask(BaseTask):
    name: str = "SeedGeneratorTask"

    def __init__(
            self,
            node_path: List[CallGraphNode],
            jazzer_sanitizer_description: Dict,
            project_source: Path,
            model: str,
            harness_filepath: Path,
            harness_name: str,
            left_harnesses_to_try: List[int]= None,
            commit_id: Optional[str] = None,
            edge_path: Optional[List[CallGraphEdge]] = None
    ):
        self.jazzer_sanitizer_description = jazzer_sanitizer_description
        self.model = model
        self.harness_filepath = harness_filepath
        self.commit_id = commit_id
        self.node_path = node_path
        self.edge_path = edge_path
        self.harness_name = harness_name
        self.project_source = project_source
        self.llm_cost = 0
        self.left_harnesses_to_try = left_harnesses_to_try
        with open(harness_filepath, "r") as f:
            self.harness_code = f.read()

    def __repr__(self):
        return (
            f"SeedGeneratorTask(\n"
            f"    path: {self.node_path!r},\n"
            f"    model: {self.model!r},\n"
            f"    harness filepath: {self.harness_filepath!r}\n"
            f")"
        )


class ReflectionAnalyzerTask(BaseTask):
    name: str = "ReflectionAnalyzerTask"

    def __init__(
            self,
            node_path: List[CallGraphNode],
            harness_name: str,
            function_indexer_path: Path,
            cp_root: Path,
            output_dir: Path,
            project_source: Path,
            query_paths: List[List[UUID]],
            model: str = "gpt-4o"
    ):
        self.node_path = node_path
        self.harness_name = harness_name
        self.function_indexer_path = function_indexer_path
        self.cp_root = cp_root
        self.model = model
        self.output_dir = output_dir
        self.query_paths = query_paths
        self.llm_cost = 0
        self.project_source = project_source

    def __repr__(self):
        return (
            f"ReflectionAnalyzerTask(\n"
            f"    cp path: {self.cp_root!r},\n"
            f"    harness name: {self.harness_name!r},\n"
            f"    function indexer path: {self.function_indexer_path!r},\n"
            f"    model: {self.model!r}\n"
            f")"
        )


class BlockerAnalyzerTask(BaseTask):
    name: str = "BlockerAnalyzerTask"

    def __init__(
            self,
            node_path: List[CallGraphNode],
            stuck_method_index: int,
            harness_name: str,
            harness_filepath: Path,
            script_path: Path,
            project_source: Path,
            source_code: str,
            attempt: int,
            jazzer_sanitizer_description: List,
            model: str = "gpt-4o"):
        super().__init__()

        self.harness_filepath = harness_filepath

        self.source_code = source_code
        self.harness_name = harness_name
        self.model = model
        self.node_path = node_path
        self.jazzer_sanitizer_description = jazzer_sanitizer_description
        self.stuck_function_name = node_path[stuck_method_index].function_name
        if stuck_method_index + 1 >= len(node_path):
            self.next_function_name = None
            self.next_function_src = None
        else:
            self.next_function_name = node_path[stuck_method_index + 1].function_name
            self.next_function_src = node_path[stuck_method_index + 1].function_code
        self.stuck_function_src = node_path[stuck_method_index].function_code
        self.llm_cost = 0
        self.attempt = attempt
        self.project_source = project_source
        with open(script_path, "r") as f:
            self.script = f.read()
        with open(self.harness_filepath, "r") as f:
            self.harness_code = f.read()
        

    def __repr__(self):
        return (
            f"BlockerAnalyzerTask(\n"
            f"    harness name: {self.harness_name!r},\n"
            f"    harness filepath: {self.harness_filepath!r},\n"
            f"    stuck function name: {self.stuck_function_name!r},\n"
            f"    next function name: {self.next_function_name!r}\n"
            f")"
        )
    
    
class SinkIdentifierTask(BaseTask):
    name: str = "SinkIdentifierTask"

    def __init__(
            self,
            methods: List[str],
            sanitizer_name: str
    ):
        self.methods = methods
        self.sanitizer_name = sanitizer_name
        self.llm_cost = 0

class WarmUpTask(BaseTask):
    name: str = "WarmUpTask"

    def __init__(
            self,
            harness_name: str,
            harness_filepath: Path,
            model: str,
            project_source: Path,
            # node_path: List[CallGraphNode],
            # edge_path: Optional[List[CallGraphEdge]] = None,
    ):
        self.harness_name = harness_name
        self.harness_filepath = harness_filepath
        self.model = model
        self.llm_cost = 0
        self.project_source = project_source
        # self.node_path = node_path
        # self.edge_path = edge_path

class SarifReportAnalyzerTask(BaseTask):
    """
    This task is to generate seeds for the given harness and sanitizer.
    """
    name: str = "SarifReportAnalyzerTask"

    def __init__(
            self, 
            sarif_report_result: SarifResult,
            jazzer_sanitizer_description: Dict,
            model: str,
            harness_filepath: Path,
            harness_name: str,
            project_source: Path, 
            attempt: int,
            function_code: str,
            data_flow_codes: List[List[str]],
            node_path: List[CallGraphNode],
            sarif_meta: SARIFMetadata,
            left_harnesses_to_try: List[int]= None,
        ):
        self.sarif_report_result = sarif_report_result
        self.jazzer_sanitizer_description = jazzer_sanitizer_description
        self.model = model
        self.harness_filepath = harness_filepath
        self.harness_name = harness_name
        self.attempt = attempt
        self.llm_cost = 0
        self.left_harnesses_to_try = left_harnesses_to_try
        self.rule_id = sarif_report_result.rule_id
        self.message = sarif_report_result.message
        self.data_flows = sarif_report_result.codeflows
        self.function_code = function_code
        self.data_flow_codes = data_flow_codes
        self.node_path = node_path
        self.project_source = project_source
        self.sarif_meta = sarif_meta

class DiffAnalyzerTask(BaseTask):
    name: str = "DiffAnalyzerTask"

    def __init__(
            self,
            jazzer_sanitizer_description: Dict,
            model: str,
            harness_filepath: Path,
            harness_name: str,
            project_source: Path,
            attempt: int,
            node_path: List[CallGraphNode],
            commit_function: str,
            call_chains: List[List[str]],
            functions_on_call_chains: List[str],
            previous_script: Optional[str] = None,
    ):
        self.jazzer_sanitizer_description = jazzer_sanitizer_description
        self.model = model
        self.harness_filepath = harness_filepath
        self.harness_name = harness_name
        self.project_source = project_source
        self.llm_cost = 0
        self.attempt = attempt
        self.node_path = node_path
        self.previous_script = previous_script
        self.commit_function = commit_function
        self.call_chains = call_chains
        self.functions_on_call_chains = functions_on_call_chains