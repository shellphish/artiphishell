import json
from collections import defaultdict
from typing import List, Optional, Set, Dict, Any
import logging
from pathlib import Path

from pydantic import Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from src.input.code_registry import CodeRegistry
from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject
from src.common.util import time_it
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.symbols import SourceLocation

from src.input.ingester import FunctionIndexIngester

class DiffguyReport(BaseObject):
    function_diff: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)
    boundary_diff: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)
    file_diff: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)
    overlap: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)
    union: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)
    heuristic: Set[FUNCTION_INDEX_KEY] = Field(default_factory=set)

    def sanitize(self) -> None:
        # Remove any empty strings
        self.function_diff.discard("")
        self.boundary_diff.discard("")
        self.file_diff.discard("")
        self.overlap.discard("")
        self.union.discard("")
        self.heuristic.discard("")


class DiffguyFilter(FilterPass):
    name: str = "diffguy"
    enabled: bool = True
    config: Dict = {}

    diff_guy_report: DiffguyReport

    @classmethod
    @time_it
    def from_report(cls, report_dir: Path) -> "DiffguyFilter":
        report_dir = Path(report_dir)

        cls.info_static(f"Loading Diffguy report from {report_dir}")

        # recursively find `diffguy_report.json` in the report_dir
        report_files = list(report_dir.glob("**/diffguy_report.json"))
        if not report_files:
            raise ValueError(f"No diffguy report found in {report_dir}")

        report_path = report_files[0]
        with open(report_path, "r") as f:
            report = json.load(f)
        report = DiffguyReport(**report)
        cls.info_static(f"Loaded {len(report.function_diff)} function diffs")
        return cls(diff_guy_report=report)

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        out = []
        for code_block in code_blocks:
            key = code_block.function_key

            weight = 0.0
            metadata = {}

            # 🔥 Top priority — function is in all diff categories
            if key in self.diff_guy_report.overlap:
                # These are the most weighted as they overlap all the diff categories, giving a shortlist of functionality
                weight = 12.0
                metadata["diffguy_category"] = "overlap"

            # ⚡ High priority — function diff + boundary diff
            elif key in self.diff_guy_report.boundary_diff and key in self.diff_guy_report.function_diff:
                weight = 7.0
                metadata["diffguy_category"] = "boundary_diff + function_diff"

            # 📈 Function became reachable — boundary + file diff
            elif key in self.diff_guy_report.boundary_diff and key in self.diff_guy_report.file_diff:
                # These codeql found are now reachable which were not reachable before the diff
                weight = 6.0
                metadata["diffguy_category"] = "boundary_diff + file_diff"

            # 🔍 Code changed and file changed — function + file diff
            elif key in self.diff_guy_report.function_diff and key in self.diff_guy_report.file_diff:
                weight = 4.0
                metadata["diffguy_category"] = "function_diff + file_diff"

            # 📂 File was touched
            elif key in self.diff_guy_report.file_diff:
                weight = 3.0
                metadata["diffguy_category"] = "file_diff"

            # ✏️ Function implementation changed
            elif key in self.diff_guy_report.function_diff:
                weight = 2.0
                metadata["diffguy_category"] = "function_diff"

            # 🔧 Function boundary shifted
            elif key in self.diff_guy_report.boundary_diff:
                weight = 4.0
                metadata["diffguy_category"] = "boundary_diff"

            res = FilterResult(weight=weight, metadata=metadata)
            code_block.filter_results[self.name] = res
            out.append(res)

        return out
