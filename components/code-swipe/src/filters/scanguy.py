from typing import Dict, List
from pydantic import Field
import json
from pathlib import Path

from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject
from src.common.util import time_it
class ScanGuyHit(BaseObject):
    additionalInfo: dict = {}
    desc: str
    startLine: str
    endLine: str
    vuln_type: str = "scanguy"
    query: str
    location: dict

class ScanGuyFunction(BaseObject):
    function_index_key: str
    function: str = None
    file: str = None
    predicted_is_vulnerable: bool = False
    predicted_vulnerability_type: str = None

class ScanGuyReport(BaseObject):
    functions: Dict[str, ScanGuyFunction] = Field(default_factory=dict)

class ScanGuyFilter(FilterPass):
    name: str = "scanguy"
    enabled: bool = True
    config: Dict = {}
    language: str = "c"  # Default, can be set to "jvm" for
    scanguy_report: ScanGuyReport

    @classmethod
    @time_it
    def from_report(cls, scan_reports_path: Path, language: str = None) -> "ScanGuyFilter":
        report_path = Path(scan_reports_path)
        # Check how many files under the directory
        validate_result_path = None
        if len(list(report_path.iterdir())) == 1:
            scan_result_path = report_path / "scan_results.json"
        elif len(list(report_path.iterdir())) == 2:
            scan_result_path = report_path / "scan_results.json"
            validate_result_path = report_path / "validate_results.json"
            cls.info_static(f"Found ScanGuy validate results at {validate_result_path}")
        cls.info_static(f"Loading ScanGuy scan results from {scan_result_path}")
        with open(scan_result_path, "r") as f:
            all_funcs = json.load(f)

        report = ScanGuyReport()
        for func in all_funcs:
            if func["predicted_is_vulnerable"].lower() == "no":
                func["predicted_is_vulnerable"] = False
            elif func["predicted_is_vulnerable"].lower() == "yes":
                func["predicted_is_vulnerable"] = True
            if "output" in func:  # Remove output field if present
                del func["output"]
            try:
                func_obj = ScanGuyFunction(**func)
            except Exception as e:
                cls.info_static(f"Error loading ScanGuy function: {json.dumps(func, indent=2)}")
                cls.warn_static(f"Error loading ScanGuy function: {e}")
                continue

            key = func_obj.function_index_key
            report.functions[key] = func_obj

        cls.info_static(f"Loaded {len(report.functions)} ScanGuy functions (language: {language})")
        return cls(scanguy_report=report, language=language)

    @classmethod
    def get_vuln_weights(cls, language: str) -> Dict[str, int]:
        """Get vulnerability weights based on language"""
        # Model is not trained on Java
        java_vuln_weight =  4 # revisit

        c_vuln_weight = 2 # revist

        if language.lower() == "jvm":
            return java_vuln_weight
        elif language.lower() in ["c", "c++"]:
            return c_vuln_weight
        else:
            return 0

    def apply(self, code_blocks: List[CodeBlock])-> List[FilterResult]:
        """Apply the ScanGuy filter to a list of code blocks."""
        results = []
        for block in code_blocks:
            if block.function_key in self.scanguy_report.functions:
                func_obj = self.scanguy_report.functions[block.function_key]
                if func_obj.predicted_is_vulnerable:
                    weight = self.get_vuln_weights(self.language)
                    result = FilterResult(
                        weight=weight
                    )
                    results.append(result)
        return results