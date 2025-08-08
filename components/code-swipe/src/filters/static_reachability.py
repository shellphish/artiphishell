from typing import List, Optional, Set, Dict, Any
import logging

from pydantic import Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from src.input.code_registry import CodeRegistry
from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject

class ReachabilityComputer(BaseObject):
    code_registry: CodeRegistry

    roots: List[CodeBlock] = Field(default_factory=list)

    reachable_blocks: Dict[str, CodeBlock] = Field(default_factory=dict)

    def locate_all_reachable_blocks(self) -> None:
        if not self.roots:
            self.warn("No roots found for static reachability computation")
            return

        for root in self.roots:
            self._locate_reachable_blocks(root)

    def is_reachable(self, code_block: CodeBlock) -> bool:
        return code_block.unique_id in self.reachable_blocks

    def _locate_reachable_blocks(self, code_block: CodeBlock, call_stack: List[str]=[]) -> None:
        if code_block.unique_id in self.reachable_blocks:
            return

        call_stack = call_stack.copy()
        call_stack.append(code_block)

        self.reachable_blocks[code_block.unique_id] = code_block

        for call in code_block.func_calls_in_func_with_fullname:
            func_blocks = self.code_registry.find_function_by_name(call)
            for func_block in func_blocks:
                self._locate_reachable_blocks(func_block, call_stack)

class SimpleReachabilityFilter(FilterPass):
    name: str = "simple_reachability"
    enabled: bool = True
    config: Dict = {}

    reachability_computer: Optional[ReachabilityComputer] = None

    def pre_process_project(self, project: OSSFuzzProject, code_registry: CodeRegistry, metadata: Dict[str, Any]) -> None:
        self.reachability_computer = ReachabilityComputer(
            code_registry=code_registry,
            roots=code_registry.entrypoint_code_blocks
        )
        metadata["simple_reachability_computer"] = self.reachability_computer

        self.reachability_computer.locate_all_reachable_blocks()

        self.debug("All reachable blocks:")
        for block in self.reachability_computer.reachable_blocks.values():
            self.debug(block.function_info.funcname)

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        out = []
        for code_block in code_blocks:
            if self.reachability_computer.is_reachable(code_block):
                res = FilterResult(
                    weight=1.0,
                    metadata={
                        "reachable": True
                    }
                )
            else:
                res = FilterResult(weight=0.0)
            code_block.filter_results[self.name] = res
            out.append(res)
        return out
