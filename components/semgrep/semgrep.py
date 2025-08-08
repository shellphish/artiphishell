#!/usr/bin/python3

import os
import json
import subprocess
import argparse
from typing import List, Dict, Optional, Any, Union
from pathlib import Path
import yaml
import glob
import logging
from collections import defaultdict

from pydantic import BaseModel, Field, ConfigDict, field_validator
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Pydantic Models for Semgrep Rules
class SemgrepMetadata(BaseModel):
    """Metadata for Semgrep rules"""
    model_config = ConfigDict(extra='allow')  # Allow additional fields

    vuln_type: str = Field(..., description="CWE identifier - required")

    cwe: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[Union[str, List[str]]] = None
    confidence: Optional[str] = None
    likelihood: Optional[str] = None
    impact: Optional[str] = None
    technology: Optional[List[str]] = None
    references: Optional[List[str]] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

    @field_validator('vuln_type')
    @classmethod
    def validate_vuln_type(cls, v):
        if not v:
            raise ValueError("vuln_type field cannot be empty")

        allowed_vuln_types = {
            'path-traversal', 'ssrf', 'out-of-bounds-write', 'out-of-bounds-write-benign', 'sql-injection',
            'command-injection', 'buffer-overflow', 'use-after-free', 'null-pointer-dereference',
            'integer-overflow', 'format-string',
            'deserialization', 'hardcoded-credentials', 'jazzer'
        }

        if v not in allowed_vuln_types:
            raise ValueError(f"vuln_type '{v}' not in allowed values: {allowed_vuln_types}")
        return v

class SemgrepRule(BaseModel):
    """Model for individual Semgrep rule validation"""
    model_config = ConfigDict(extra='allow')

    # Required fields based on your examples
    rule_id: str = Field(..., alias='id', description="Unique rule identifier")
    message: str = Field(..., description="Rule description message")
    severity: str = Field(..., description="Rule severity level")
    languages: List[str] = Field(..., description="Target programming languages")

    # Optional fields
    metadata: SemgrepMetadata = Field(..., description="Rule metadata with required vuln_type")
    fix: Optional[str] = None

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        allowed_severities = {'ERROR', 'WARNING', 'INFO'}
        if v.upper() not in allowed_severities:
            raise ValueError(f"Severity '{v}' not in recommended values: {allowed_severities}")
        return v

class SemgrepRuleFile(BaseModel):
    """Model for complete Semgrep rule file"""
    rules: List[SemgrepRule] = Field(..., description="List of Semgrep rules")

class SemgrepFinding(BaseModel):
    """Model for processed Semgrep finding - matches your process_finding structure"""
    check_id: str = Field(..., description="Rule check ID")
    severity: str = Field(..., description="Finding severity")
    file_path: str = Field(..., description="Path to the file with finding")
    start_line: int = Field(..., description="Starting line number")
    message: str = Field(..., description="Finding message")
    vuln_type: str = Field(..., description="CWE identifier - required")
    end_line: Optional[int] = None

class VulnerableFunction(BaseModel):
    """Model for vulnerable function with its findings"""
    function_key: str = Field(..., description="Unique function identifier")
    number_of_findings: int = Field(..., description="Total number of findings in this function")
    findings: List[SemgrepFinding] = Field(..., description="List of findings in this function")

    # Optional function metadata
    function_name: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None

class AnalysisResults(BaseModel):
    """Model for complete analysis results"""
    repo_path: str = Field(..., description="Path to analyzed repository")
    total_findings: int = Field(..., description="Total number of findings")
    total_vulnerable_functions: int = Field(..., description="Total number of vulnerable functions")
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_rule: Dict[str, int] = Field(default_factory=dict)
    raw_findings: List[SemgrepFinding] = Field(..., description="All raw findings")
    vulnerable_functions: Dict[str, VulnerableFunction] = Field(
        default_factory=dict,
        description="Vulnerable functions mapped by function key"
    )


class SemgrepAnalysis:
    def __init__(self, repo_path: str, rules_dir: str, full_functions_indices: str,
                 functions_json_dir: str, raw_findings_file_path: str,
                 vulnerable_functions_file_path: str, cp_name: Optional[str] = None,
                 project_id: Optional[str] = None, local_run: bool = False):

        self.repo_path = Path(repo_path).resolve()
        self.rules_dir = Path(rules_dir).resolve()
        self.full_functions_indices = Path(full_functions_indices).resolve()
        self.functions_json_dir = Path(functions_json_dir).resolve()
        self.raw_findings_file_path = Path(raw_findings_file_path).resolve()
        self.vulnerable_functions_file_path = Path(vulnerable_functions_file_path).resolve()

        # Initialize function resolver
        if local_run:
            self.function_resolver = LocalFunctionResolver(
                str(self.full_functions_indices),
                str(self.functions_json_dir)
            )
        else:
            self.function_resolver = RemoteFunctionResolver(cp_name, project_id)

        # Initialize results
        self.validated_rules: List[SemgrepRule] = []
        self.analysis_results: Optional[AnalysisResults] = None

    def _validate_rules(self) -> List[Path]:
        """Validate all rule files and return valid ones"""
        rule_files = []
        rule_files.extend(self.rules_dir.glob('**/*.yml'))
        rule_files.extend(self.rules_dir.glob('**/*.yaml'))

        if not rule_files:
            logger.error(f"No .yml/.yaml rule files found in {self.rules_dir}")
            return []

        validated_files = []
        total_rules = 0

        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_content = yaml.safe_load(f)

                # Validate the rule file structure
                rule_file_model = SemgrepRuleFile(**rule_content)
                self.validated_rules.extend(rule_file_model.rules)
                validated_files.append(rule_file)
                total_rules += len(rule_file_model.rules)

                logger.info(f"✅ Validated {rule_file.parent.name}/{rule_file.name}: {len(rule_file_model.rules)} rules")

            except Exception as e:
                logger.error(f"❌ Failed to validate {rule_file.parent.name}/{rule_file.name}: {str(e)}")
                # Optionally continue with invalid rules or fail fast
                continue

        logger.info(f"Total validated rules: {total_rules} from {len(validated_files)} files")
        return validated_files

    def _process_finding(self, finding: Dict[str, Any]) -> Optional[SemgrepFinding]:
        """Process a single Semgrep finding into our model"""
        try:
            extra = finding.get('extra', {})
            metadata = extra.get('metadata', {})
            file_path = finding.get('path', '')
            vuln_type = metadata.get('vuln_type', '')

            check_id = finding.get('check_id', '')
            if not check_id:
                logger.warning(f"Skipping finding with missing required fields: check_id={check_id}, file_path={file_path}, vuln_type={vuln_type}")
                return None

            return SemgrepFinding(
                check_id=check_id,
                severity=extra.get('severity', ''),
                file_path=finding.get('path', ''),
                start_line=finding.get('start', {}).get('line', 0),
                message=extra.get('message', ''),
                vuln_type=metadata.get('vuln_type', '')
            )
        except Exception as e:
            logger.warning(f"Failed to process finding: {e}")
            return None

    def _run_git_config(self) -> bool:
        """Configure git to mark repository as safe"""
        try:
            subprocess.run(
                ["git", "config", "--global", "--add", "safe.directory", str(self.repo_path)],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Marked repository as safe: {self.repo_path}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to mark repository as safe: {e.stderr}")
            return False

    def _run_semgrep_on_rules(self, rule_files: List[Path]) -> List[SemgrepFinding]:
        """Run Semgrep on validated rule files"""
        all_findings = []

        for rule_file in rule_files:
            logger.info(f"Processing rule file: {rule_file.name}")
            try:
                result = subprocess.run(
                    ["semgrep", "scan", "--config", str(rule_file), str(self.repo_path), "--json"],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    try:
                        results = json.loads(result.stdout)
                        if results and 'results' in results:
                            for finding in results['results']:
                                processed_finding = self._process_finding(finding)
                                if processed_finding:
                                    all_findings.append(processed_finding)
                                else:
                                    logger.warning(f"Skipping finding: {finding}")

                            logger.info(f"Found {len(results['results'])} findings in {rule_file.name}")
                        else:
                            logger.info(f"No results found in {rule_file.name}")

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON output from {rule_file.name}: {e}")
                else:
                    logger.warning(f"Semgrep returned non-zero exit code for {rule_file.name}: {result.returncode}")
                    if result.stderr:
                        logger.debug(f"STDERR: {result.stderr}")

            except Exception as e:
                logger.error(f"Error processing rule {rule_file.name}: {str(e)}")
                continue

        return all_findings

    def _process_vulnerable_functions(self, findings: List[SemgrepFinding]) -> Dict[str, VulnerableFunction]:
        """Process findings to identify vulnerable functions"""
        # Group findings by file
        findings_by_file = defaultdict(list)
        for finding in findings:
            findings_by_file[finding.file_path].append(finding)

        vulnerable_functions = {}

        for file_path, file_findings in findings_by_file.items():
            # Create line-to-function mapping
            line_to_function = {}

            try:
                function_keys = self.function_resolver.find_by_filename(Path(file_path).name)
                for function_key in function_keys:
                    start_line, end_line = self.function_resolver.get_function_boundary(function_key)
                    for line in range(start_line, end_line + 1):
                        line_to_function[line] = function_key
            except Exception as e:
                logger.warning(f"Could not resolve functions for {file_path}: {e}")
                continue

            # Map findings to functions
            function_findings = defaultdict(list)
            for finding in file_findings:
                if finding.start_line in line_to_function:
                    function_key = line_to_function[finding.start_line]
                    function_findings[function_key].append(finding)

            for function_key, func_findings in function_findings.items():
                try:
                    start_line, end_line = self.function_resolver.get_function_boundary(function_key)
                    # 🔁 Inject end_line into each finding object
                    for finding in func_findings:
                        finding.end_line = end_line

                    vulnerable_functions[function_key] = VulnerableFunction(
                        function_key=function_key,
                        number_of_findings=len(func_findings),
                        findings=func_findings,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line
                    )

                    logger.info(f"Vulnerable {function_key} with {len(func_findings)} findings")
                    for finding in func_findings:
                        logger.debug(f"  - {finding.model_dump()}")

                except Exception as e:
                    logger.warning(f"Could not create VulnerableFunction for {function_key}: {e}")
                    # Create minimal version
                    vulnerable_functions[function_key] = VulnerableFunction(
                        function_key=function_key,
                        number_of_findings=len(func_findings),
                        findings=func_findings
                    )

        return vulnerable_functions

    def _create_analysis_results(self, findings: List[SemgrepFinding],
                               vulnerable_functions: Dict[str, VulnerableFunction]) -> AnalysisResults:
        """Create the final analysis results model"""
        # Calculate statistics
        findings_by_severity = defaultdict(int)
        findings_by_rule = defaultdict(int)

        for finding in findings:
            findings_by_severity[finding.severity] += 1
            findings_by_rule[finding.check_id] += 1

        return AnalysisResults(
            repo_path=str(self.repo_path),
            total_findings=len(findings),
            total_vulnerable_functions=len(vulnerable_functions),
            findings_by_severity=dict(findings_by_severity),
            findings_by_rule=dict(findings_by_rule),
            raw_findings=findings,
            vulnerable_functions=vulnerable_functions
        )

    def _save_results(self) -> None:
        """Save analysis results to files"""
        if not self.analysis_results:
            logger.error("No analysis results to save")
            return

        # Save raw findings
        raw_findings_data = {
            'repo_path': self.analysis_results.repo_path,
            'total_findings': self.analysis_results.total_findings,
            'findings_by_severity': self.analysis_results.findings_by_severity,
            'findings_by_rule': self.analysis_results.findings_by_rule,
            'findings': [finding.model_dump() for finding in self.analysis_results.raw_findings]
        }

        with open(self.raw_findings_file_path, 'w') as f:
            json.dump(raw_findings_data, f, indent=2)
        logger.info(f"Raw findings saved to {self.raw_findings_file_path}")

        # Save vulnerable functions
        vulnerable_functions_data = {
            function_key: vuln_func.model_dump()
            for function_key, vuln_func in self.analysis_results.vulnerable_functions.items()
        }

        with open(self.vulnerable_functions_file_path, 'w') as f:
            json.dump(vulnerable_functions_data, f, indent=2)
        logger.info(f"Vulnerable functions saved to {self.vulnerable_functions_file_path}")

    def run(self) -> Optional[AnalysisResults]:
        """Run the complete Semgrep analysis pipeline"""
        logger.info("🚀 Starting Semgrep analysis pipeline...")

        # Step 1: Configure git
        if not self._run_git_config():
            return None

        # Step 2: Validate rules
        logger.info("📋 Validating Semgrep rules...")
        validated_rule_files = self._validate_rules()
        if not validated_rule_files:
            logger.error("No valid rules found. Exiting.")
            return None

        # Step 3: Run Semgrep
        logger.info("🔍 Running Semgrep analysis...")
        findings = self._run_semgrep_on_rules(validated_rule_files)

        if not findings:
            logger.warning("No findings detected across all rules.")
            # Still create results object for consistency
            findings = []

        # Step 4: Process vulnerable functions
        logger.info("🎯 Processing vulnerable functions...")
        vulnerable_functions = self._process_vulnerable_functions(findings)

        # Step 5: Create final results
        self.analysis_results = self._create_analysis_results(findings, vulnerable_functions)

        # Step 6: Save results
        logger.info("💾 Saving results...")
        self._save_results()

        # Step 7: Log summary
        logger.info("📊 Analysis Summary:")
        logger.info(f"  Total findings: {self.analysis_results.total_findings}")
        logger.info(f"  Vulnerable functions: {self.analysis_results.total_vulnerable_functions}")
        logger.info(f"  Findings by severity: {dict(self.analysis_results.findings_by_severity)}")

        logger.info("✅ Analysis completed successfully!")
        return self.analysis_results

def main():
    parser = argparse.ArgumentParser(description='Run Semgrep pipeline on a repository')
    parser.add_argument('--repo_path', required=True,
                      help='Path to the repository to analyze')
    parser.add_argument('--rules_dir', required=True,
                      help='Path to the rules directory')
    parser.add_argument('--full_functions_indices', required=True,
                      help='Path to the functions index')
    parser.add_argument('--functions_json_dir', required=True,
                      help='Path to function JSON files')
    parser.add_argument('--raw_findings_file_path', required=True,
                      help='Path to save raw findings')
    parser.add_argument('--vulnerable_functions_file_path', required=True,
                      help='Path to save vulnerable functions')
    parser.add_argument('--cp-name', required=False,
                      help='cp name')
    parser.add_argument('--project-id', required=False,
                      help='project id')
    parser.add_argument('--local-run', action='store_true', required=False, default=False,
                      help='enable to use local function resolver')

    args = parser.parse_args()

    # Run pipeline
    try:
        semgrep_analysis = SemgrepAnalysis(
            args.repo_path,
            args.rules_dir,
            args.full_functions_indices,
            args.functions_json_dir,
            args.raw_findings_file_path,
            args.vulnerable_functions_file_path,
            args.cp_name,
            args.project_id,
            args.local_run
        )
        semgrep_analysis.run()

    except Exception as e:
        logger.error(f"Error in semgrep analysis: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()