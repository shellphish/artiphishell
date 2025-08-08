import json
from typing import Dict, List, Set, Any
from pathlib import Path
from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject
from pydantic import Field, field_validator

BASE_WEIGHT_RATIO = 1 / 2
RELATED_LOCATION_RATIO = 0.2  # 20% of direct weight distributed to related functions

class CodeFlowFunctions(BaseObject):
    flow_data: Dict[str, List[str]] = Field(default_factory=dict)

class CodeqlCWEFinding(BaseObject):
    level: str
    start_line: int
    rule_id: str
    message: str
    description: str = None
    short_description: str = None
    security_severity: str = None
    code_flow_functions: CodeFlowFunctions = Field(default_factory=CodeFlowFunctions)
    cwe_tags: List[str] = Field(default_factory=list)
    related_locations_functions: List[str] = Field(default_factory=list)

class CodeqlCWEFunction(BaseObject):
    function_name: str
    findings: List[CodeqlCWEFinding] = Field(default_factory=list)

class CodeqlCWEReport(BaseObject):
    function_data: Dict[str, CodeqlCWEFunction] = Field(default_factory=dict)

class CodeqlCWEFilter(FilterPass):
    """Filter that prioritizes functions based on CodeqlCWE findings"""
    name: str = "CodeqlCWE"
    enabled: bool = True
    weight_mode: str = "combined"  # "base_weight", "customized_weight", "combined"
    language: str = "jvm"  # Default language
    CodeqlCWE_report: CodeqlCWEReport
    is_negative: bool = False

    @classmethod
    def from_report(cls, report_path: Path, language, weight_mode="combined", is_negative=False) -> "CodeqlCWEFilter":
        """Create filter from a report file"""
        report_path = Path(report_path)
        if not report_path.exists():
            raise ValueError(f"No CodeqlCWE report found in {report_path}")

        with open(report_path, "r") as f:
            report = json.load(f)

        function_data = {}

        language = report.get("metadata", {}).get("language", "jvm")

        # Handle new report format with 'vulnerable_functions' key
        vulnerable_functions = report.get("vulnerable_functions", {})

        for function_key, function_info in vulnerable_functions.items():
            findings = []
            # experimental: sometimes same rule hits in same function make that rule over powering.
            seen_rule_ids = set()
            results_data = function_info.get("results", [])

            for result_data in results_data:
                rule_id = result_data.get("rule_id", "")
                if rule_id and rule_id in seen_rule_ids:
                    continue

                # Map the new format to our existing structure
                finding_dict = {
                    "level": result_data.get("level", "").upper(),
                    "start_line": result_data.get("start_line", 0),
                    "rule_id": result_data.get("rule_id", ""),
                    "message": result_data.get("message", ""),
                    "description": result_data.get("description", ""),
                    "short_description": result_data.get("short_description", ""),
                    "security_severity": result_data.get("security_severity", ""),
                    "cwe_tags": result_data.get("cwe_tags", []),
                    "code_flow_functions": CodeFlowFunctions(
                        flow_data=result_data.get("code_flow_functions", {})
                    ),
                    "related_locations_functions": result_data.get("related_locations_functions", [])
                }

                finding = CodeqlCWEFinding(**finding_dict)
                findings.append(finding)
                seen_rule_ids.add(rule_id)

            function_data[function_key] = CodeqlCWEFunction(
                function_name=function_key,
                findings=findings
            )

        CodeqlCWE_report = CodeqlCWEReport(function_data=function_data)
        return cls(CodeqlCWE_report=CodeqlCWE_report, language=language, weight_mode=weight_mode, is_negative=is_negative)

    @classmethod
    def get_customized_weights(cls, language: str) -> Dict[str, float]:
        """Get vulnerability weights based on language"""

        java_customized_weights = {

            "java/zipslip": 6,                              # codeql sev score: 7.5   # high
            "java/xxe": 5,                                  # codeql sev score: 9.1   # high
            "java/unsafe-deserialization": 5.5,             # codeql sev score: 9.8   # high
            "java/ssrf": 5.5,                               # codeql sev score: 9.1   # high
            "java/command-line-injection": 4,               # codeql sev score: 9.8   # high
            "java/xss": 4,                                  # codeql sev score: 6.1
            "java/partial-path-traversal": 3,               # codeql sev score: 9.3   # med
            "java/path-injection": 2.5,                     # codeql sev score: 7.5   # low
            "java/redos": 4.5,                              # codeql sev score: 7.5   # high

            "java/log-injection": 0.5,                      # codeql sev score: 7.8   # super low [has many FPs, could be useful # may delete later]
            "java/hardcoded-credential-api-call": 1.5,      # codeql sev score: 9.8   # low
            "java/toctou-race-condition": 1.5,              # codeql sev score: 7.7   # low  # was useful in logic stuff
            "java/tainted-numeric-cast": 1.5,               # codeql sev score: 9     # med

            "java/relative-path-command": 1.5,               # codeql sev score: 5.4 (warning)  # low or med

            "java/zipslip-urldecoding": 5,          # custom query for tika
            "java/BigDecimalDOS-Local": 4,                # custom query for apache-commons-compress
            # robably delete below rules if there's too much noise in ranking
            # These are from quality ql pack
            "java/index-out-of-bounds": 0.5,                                            # low
            "java/dereferenced-value-is-always-null": 0.5,                              # low

            "java/uncontrolled-file-decompression": 1,         # codeql sev score: 7.8   # low
            "java/unsafe-hostname-verification": 0.5,          # codeql sev score: 5.9   # low
            "java/insecure-rmi-jmx-server-initialization": 0.5 # NA
        }



        c_customized_weights = {
            # "buffer-overflow": 4,
            # "stack-buffer-overflow": 5,
            # "heap-buffer-overflow": 5,
            # "out-of-bounds-read": 5,
            # "integer-overflow": 5,
            # "resource-exhaustion": 5,
            # "double-free": 5,
            # "use-after-free": 5,
            # "null-pointer-dereference": 5,
            # "malicious-code": 4,
            # "out-of-bounds-write": 4,

            # TODO: add more customized weights for c
        }


        if language.lower() == "jvm":
            return java_customized_weights
        elif language.lower() in ["c", "c++"]:
            return c_customized_weights
        else:
            # Return empty dict for unknown languages
            return {}

    def get_base_weights(self, finding: CodeqlCWEFinding) -> float:
        """Get base weight by taking security severity * a ratio """
        try:
            # Convert security_severity string to float before multiplication
            security_severity_value = float(finding.security_severity) if finding.security_severity else 0.0
            base_weight = security_severity_value * BASE_WEIGHT_RATIO
            return base_weight
        except (ValueError, TypeError):
            # If conversion fails, return 0.0 as fallback
            return 0.0

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        """Apply the filter to code blocks using two-pass approach for related location weights"""
        results = []
        # Updated customized weights
        customized_weights = CodeqlCWEFilter.get_customized_weights(self.language)

        self.info(f"Applying CodeqlCWE filter with mode: {self.weight_mode}, is_negative: {self.is_negative}, base_weight_ratio: {BASE_WEIGHT_RATIO}, related_location_ratio: {RELATED_LOCATION_RATIO}")

        # Create function_key to block mapping for efficient lookup
        function_key_to_block = {block.function_key: block for block in code_blocks}

        # PASS 1: Calculate direct weights for functions with CWE findings
        direct_weights = {}  # function_key -> direct_weight
        all_findings_metadata = {}  # function_key -> findings_metadata

        for block in code_blocks:
            direct_weight = 0.0
            findings_metadata = []
            if block.function_key in self.CodeqlCWE_report.function_data:
                CodeqlCWE_function = self.CodeqlCWE_report.function_data[block.function_key]

                if self.weight_mode == "base_weight":
                    for finding in CodeqlCWE_function.findings:
                        base_weight = self.get_base_weights(finding)
                        findings_metadata.append(finding.rule_id)
                        direct_weight += base_weight
                elif self.weight_mode == "customized_weight":
                    for finding in CodeqlCWE_function.findings:
                        customized_weight = customized_weights.get(finding.rule_id, 0.0) if finding.rule_id else 0.0
                        findings_metadata.append(finding.rule_id)
                        direct_weight += customized_weight
                elif self.weight_mode == "combined":
                    for finding in CodeqlCWE_function.findings:
                        base_weight = self.get_base_weights(finding)
                        customized_weight = customized_weights.get(finding.rule_id, 0.0) if finding.rule_id else 0.0
                        findings_metadata.append(finding.rule_id)
                        direct_weight += base_weight + customized_weight

            direct_weights[block.function_key] = direct_weight
            all_findings_metadata[block.function_key] = findings_metadata

        # PASS 2: Calculate related location weights
        related_weights = {block.function_key: 0.0 for block in code_blocks}

        for block in code_blocks:
            if block.function_key in self.CodeqlCWE_report.function_data:
                CodeqlCWE_function = self.CodeqlCWE_report.function_data[block.function_key]
                function_direct_weight = direct_weights[block.function_key]

                # Distribute weight to related location functions
                for finding in CodeqlCWE_function.findings:
                    for related_func_key in finding.related_locations_functions:
                        if related_func_key in related_weights:  # Only if the related function is in our code blocks
                            related_weights[related_func_key] += RELATED_LOCATION_RATIO * function_direct_weight

        # Log statistics about related location weight distribution
        functions_with_related_weight = sum(1 for weight in related_weights.values() if weight > 0)
        total_related_weight = sum(related_weights.values())
        self.info(f"Distributed related location weights to {functions_with_related_weight} functions, total related weight: {total_related_weight:.2f}")

        # FINAL: Combine direct and related weights
        for block in code_blocks:
            final_weight = direct_weights[block.function_key] + related_weights[block.function_key]

            # Build metadata
            metadata = {}
            if all_findings_metadata[block.function_key]:
                metadata["codeql_cwe_queries"] = all_findings_metadata[block.function_key]

            # Add related weight info to metadata if there's any related weight
            if related_weights[block.function_key] > 0:
                metadata["related_location_weight"] = related_weights[block.function_key]

            if self.is_negative:
                final_weight = -final_weight

            result = FilterResult(weight=final_weight, metadata=metadata)
            block.filter_results[self.name] = result
            results.append(result)

        return results