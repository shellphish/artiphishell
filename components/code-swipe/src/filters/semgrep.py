import json
from typing import Dict, List, Set
from pathlib import Path

from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject
from pydantic import Field, field_validator

class SemgrepFinding(BaseObject):
    severity: str
    start_line: int
    end_line: int
    vuln_type: str
    check_id: str
    message: str
    file_path: str # TODO: remove this field after updating semgrep report

class SemgrepFunction(BaseObject):
    function_name: str
    findings: List[SemgrepFinding] = Field(default_factory=list)

class SemgrepReport(BaseObject):
    function_data: Dict[str, SemgrepFunction] = Field(default_factory=dict)

class SemgrepFilter(FilterPass):
    """Filter that prioritizes functions based on semgrep findings"""
    name: str = "semgrep"
    enabled: bool = True
    weight_mode: str = "severity_only"  # "severity_only", "vuln_type", or "combined"
    semgrep_report: SemgrepReport
    is_negative: bool = False

    @classmethod
    def from_report(cls, report_path: Path, weight_mode="severity_only", is_negative=False) -> "SemgrepFilter":
        """Create filter from a report file"""
        report_path = Path(report_path)

        if not report_path.exists():
            raise ValueError(f"No semgrep report found in {report_path}")

        with open(report_path, "r") as f:
            report = json.load(f)
        function_data = {}
        for function_name, data in report.items():
            findings = []
            findings_data = data.get("findings", [])

            for finding_data in findings_data:
                finding = SemgrepFinding(**finding_data)
                findings.append(finding)

            function_data[function_name] = SemgrepFunction(
                function_name=function_name,
                findings=findings
            )

        semgrep_report = SemgrepReport(function_data=function_data)
        return cls(semgrep_report=semgrep_report, weight_mode=weight_mode, is_negative=is_negative)

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        """Apply the filter to code blocks"""
        results = []

        #TODO: update weights
        sev_weights = {"ERROR": 10.0, "WARNING": 5.0, "INFO": 2.0}
        vuln_type_weights = {"jazzer": 10.0,
                             "out-of-bounds-write": 9.0,
                             "out-of-bounds-write-benign": 2.0,
                             "deserialization": 4.0,
                             "path-traversal": 2.5}
        # add c types as well
        self.info(f"Applying Semgrep filter with mode: {self.weight_mode}, is_negative: {self.is_negative}")
        for block in code_blocks:
            weight = 0.0
            metadata = {}

            if block.function_key in self.semgrep_report.function_data:
                semgrep_function = self.semgrep_report.function_data[block.function_key]
                unique_severities = set(finding.severity for finding in semgrep_function.findings if finding.severity)
                unique_vuln_types = set(finding.vuln_type for finding in semgrep_function.findings if finding.vuln_type)
                severity_total = sum(sev_weights.get(sev, 0.0) for sev in unique_severities)
                vuln_type_total = sum(vuln_type_weights.get(vt, 1.0) for vt in unique_vuln_types)
                self.info(f"Function {block.function_key} has {len(semgrep_function.findings)} findings")

                # Collect check_id for each finding
                findings_metadata = list(set(finding.check_id for finding in semgrep_function.findings if finding.check_id))
                metadata = {"semgrep": findings_metadata}

                # Calculate weight based on mode
                if self.weight_mode == "severity_only":
                    weight = severity_total
                elif self.weight_mode == "vuln_type":
                    weight = vuln_type_total
                elif self.weight_mode == "combined":
                    weight = severity_total + vuln_type_total

            if self.is_negative:
                weight = -weight

            result = FilterResult(weight=weight, metadata=metadata)
            block.filter_results[self.name] = result
            results.append(result)

        return results