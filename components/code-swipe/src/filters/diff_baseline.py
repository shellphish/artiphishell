from typing import List, Optional, Set, Dict, Any
import logging

from pydantic import Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver

from src.input.code_registry import CodeRegistry
from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject

class DiffBaselineFilter(FilterPass):
    name: str = "diff_baseline"
    enabled: bool = True
    config: Dict = {}

    changed_functions_index_path: str
    changed_functions_jsons_dir: str

    changed_functions: Dict[str, Any] = {}

    def pre_process_project(self, project: OSSFuzzProject, code_registry: CodeRegistry, metadata: Dict[str, Any]) -> None:

        self.info(f"Loading changed functions from {self.changed_functions_index_path} and {self.changed_functions_jsons_dir}")
        # Must use local resolver for changed files
        resolver = LocalFunctionResolver(
            functions_index_path=self.changed_functions_index_path,
            functions_jsons_path=self.changed_functions_jsons_dir
        )

        all_changed_functions = resolver.get_filtered('true', '.value.focus_repo_relative_path != null')

        # This probably is a list but maybe its also a dict?
        if isinstance(all_changed_functions, list):
            all_changed_functions = {k: resolver.get(k) for k in all_changed_functions}

        self.info(f"Found {len(all_changed_functions)} functions total in the diff")

        self.changed_functions = all_changed_functions

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        out = []
        matching_keys = set()
        for code_block in code_blocks:
            key = code_block.function_key
            func_name = code_block.funcname
            file_name = code_block.function_info.filename
            full_file_path = key[:key.find(":")]

            weight = 0
            metadata = {}

            if key in self.changed_functions:
                weight = 20
                metadata["diff_baseline"] = True
                matching_keys.add(key)

            res = FilterResult(weight=weight, metadata=metadata)
            code_block.filter_results[self.name] = res
            out.append(res)

        for f in self.changed_functions:
            if f not in matching_keys:
                # TODO try to match these up
                self.warn(f"Changed function {f} not found in code blocks")

        self.warn(f"Found {len(matching_keys)}/{len(self.changed_functions)} matching changed functions")
        
        return out



