import argparse
import json
import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Union

# Analysis graph imports
from analysis_graph.models.cfg import CFGFunction, CWEVulnerability
from neomodel import config
from shellphish_crs_utils.function_resolver import (
    LocalFunctionResolver,
    RemoteFunctionResolver,
)
from shellphish_crs_utils.sarif_resolver import SarifResolver

# Configuration
config.DATABASE_URL = os.environ.get(
    "ANALYSIS_GRAPH_BOLT_URL", "bolt://neo4j:helloworldpdt@localhost:7687"
)
if os.getenv("CRS_TASK_NUM"):
    config.DATABASE_URL = config.DATABASE_URL.replace(
        "TASKNUM", os.getenv("CRS_TASK_NUM")
    )
else:
    if "TASKNUM" in config.DATABASE_URL:
        raise ValueError(
            "Env CRS_TASK_NUM is not set but ANALYSIS_GRAPH_BOLT_URL contains TASKNUM"
        )

logging.basicConfig()
_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

DEFAULT_TIMEOUT = 1800
ALLOWLIST_RULES = ["java/toctou-race-condition", "java/relative-path-command"]


def cleanup_existing_cwe_data():
    """
    Clean up existing CWE vulnerability data from the analysis graph.
    This removes all CWE vulnerabilities and their relationships.
    """
    try:
        _l.info("Cleaning up existing CWE vulnerability data...")

        # Get all CWE vulnerability nodes
        cwe_nodes = CWEVulnerability.nodes.all()
        count = len(cwe_nodes)

        if count > 0:
            _l.info(f"Found {count} existing CWE vulnerability nodes, deleting...")

            # Delete all CWE vulnerability nodes (this will also delete relationships)
            for cwe_node in cwe_nodes:
                cwe_node.delete()

            _l.info(f"Deleted {count} CWE vulnerability nodes and their relationships")
        else:
            _l.info("No existing CWE vulnerability data found")

    except Exception as e:
        _l.warning(f"Error during cleanup: {e}")


def upload_to_analysis_graph(resolved_results):
    """
    Upload CWE vulnerability results to the analysis graph.

    Args:
        resolved_results: The resolved CWE report containing vulnerable functions
    """
    try:
        vulnerable_functions = resolved_results.get("vulnerable_functions", {})

        _l.info(
            f"Uploading {len(vulnerable_functions)} vulnerable functions to analysis graph"
        )

        uploaded_vulnerabilities = 0

        for keyindex, func_data in vulnerable_functions.items():
            try:
                # Get or create the CFGFunction using the keyindex as identifier
                cfg_function = CFGFunction.get_or_create({"identifier": keyindex})[0]

                # Process each vulnerability result for this function
                for result in func_data.get("results", []):
                    try:
                        rule_id = result.get("rule_id")
                        cwe_tags = result.get("cwe_tags", [])
                        description = result.get("description", "")
                        start_line = result.get("start_line")
                        code_flow_functions = result.get("code_flow_functions", {})
                        related_locations_functions = result.get(
                            "related_locations_functions", []
                        )

                        # Debug: Print what we got
                        _l.debug(
                            f"Processing {keyindex} -> {rule_id}: code_flow_functions = {code_flow_functions}"
                        )
                        _l.debug(
                            f"Processing {keyindex} -> {rule_id}: related_locations_functions = {related_locations_functions}"
                        )

                        # Convert to list of lists format (consistent with successful test)
                        codeflow_functions_data = []
                        if code_flow_functions:
                            # Sort by flow ID to maintain consistent ordering
                            for flow_id in sorted(code_flow_functions.keys()):
                                flow_functions = code_flow_functions[flow_id]
                                if flow_functions:  # Only add non-empty flows
                                    codeflow_functions_data.append(flow_functions)

                        # Debug: Print the converted data
                        _l.debug(
                            f"Converted codeflow_functions_data = {codeflow_functions_data}"
                        )
                        _l.debug(
                            f"Type: {type(codeflow_functions_data)}, Length: {len(codeflow_functions_data)}"
                        )
                        if codeflow_functions_data:
                            _l.debug(
                                f"First element: {codeflow_functions_data[0]}, Type: {type(codeflow_functions_data[0])}"
                            )

                        # Get or create the CWEVulnerability
                        cwe_vuln = CWEVulnerability.get_or_create(
                            {
                                "rule_id": rule_id,
                                "cwe_tags": cwe_tags,
                                "level": result.get("level", ""),
                                "security_severity": result.get(
                                    "security_severity", ""
                                ),
                                "description": description,
                            }
                        )[0]

                        # Check if relationship already exists to avoid duplicates
                        if not cfg_function.has_cwe_vulnerability.is_connected(
                            cwe_vuln
                        ):
                            # Store metadata with proper data types
                            metadata = {
                                "line_number": start_line
                                if start_line is not None
                                else 0,
                            }

                            # Only add codeflow_functions if there's actual data
                            if codeflow_functions_data:
                                metadata["codeflow_functions"] = codeflow_functions_data

                            # Only add related_locations_functions if there's actual data
                            if related_locations_functions:
                                metadata["related_locations_functions"] = (
                                    related_locations_functions
                                )

                            # Create the relationship with metadata
                            cfg_function.has_cwe_vulnerability.connect(
                                cwe_vuln, metadata
                            )

                            uploaded_vulnerabilities += 1
                            _l.debug(
                                f"Connected function {keyindex} to vulnerability {rule_id} with {len(codeflow_functions_data)} codeflows and {len(related_locations_functions)} related locations"
                            )
                        else:
                            _l.debug(
                                f"Relationship already exists between {keyindex} and {rule_id}"
                            )

                    except Exception as e:
                        _l.warning(
                            f"Error processing vulnerability result {result}: {e}"
                        )
                        continue

            except Exception as e:
                _l.warning(f"Error processing function {keyindex}: {e}")
                continue

        _l.info(
            f"Successfully uploaded {uploaded_vulnerabilities} vulnerability relationships to analysis graph"
        )

    except Exception as e:
        _l.error(f"Error uploading to analysis graph: {e}")
        raise


def run_cwe_query(
    codeql_database_path: Path,
    codeql_cwe_sarif_report_path: str,
    codeql_cwe_report_path: str,
    func_resolver: Union[LocalFunctionResolver, RemoteFunctionResolver],
    language: str,
    collect_rules_stats: bool = False,
):
    """
    Run CWE queries and parse results into a structured format.

    Args:
        client: CodeQL client instance
        project_name: Name of the project in CodeQL database
        project_id: ID of the project in CodeQL database
        codeql_cwe_sarif_report_path: Path to save the raw SARIF report
        codeql_cwe_report_path: Path to save the resolved/parsed report
        func_resolver: Function resolver for location mapping
        language: Programming language of the project
        collect_rules_stats: Whether to collect rules statistics

    Returns:
        List of SARIF results from the resolver
    """
    # Get the CWE list based on the language
    # Map target language to list of source languages
    lang_mapping = {
        "java": ["jvm", "java"],
        "cpp": ["c", "cpp", "c++"],
    }

    target_lang = next(
        (target for target, sources in lang_mapping.items() if language in sources),
        None,
    )

    assert target_lang is not None, f"Unsupported language: {language}"

    queries = [
        f"codeql/{target_lang}-queries:codeql-suites/{target_lang}-security-experimental.qls",
        f"codeql/{target_lang}-queries:codeql-suites/{target_lang}-security-extended.qls",
    ]

    cmd = [
        "codeql",
        "database",
        "analyze",
        "--format=sarif-latest",
        "--output=" + codeql_cwe_sarif_report_path,
        "--threads=0",  # Use all available threads
        f"--ram={11*1024}",
    ]

    additional_packs = [
        str(entry)
        for entry in Path("/shellphish/codeql_compiled_packs").iterdir()
        if entry.is_dir()
    ]

    if additional_packs:
        cmd += ["--additional-packs=" + ":".join(additional_packs)]

    cmd += ["--", Path(codeql_database_path).absolute().as_posix()]
    cmd += queries

    try:
        subprocess.run(
            cmd,
            check=True,
            timeout=DEFAULT_TIMEOUT,
        )

        _l.info(
            f"CodeQL analysis completed successfully, SARIF report saved to {codeql_cwe_sarif_report_path}"
        )
    except (subprocess.TimeoutExpired, TimeoutError):
        _l.warning(f"CodeQL analysis timed out after {DEFAULT_TIMEOUT} seconds, returning empty report")

        # Return empty report structure
        empty_cwe_report_results = {
            "metadata": {
                "language": language,
                "total_vulnerable_functions": 0,
                "total_vulnerabilities": 0,
                "findings_per_rule_id": {},
            },
            "vulnerable_functions": {},
        }

        # Save empty report
        with open(codeql_cwe_report_path, "w") as f:
            json.dump(empty_cwe_report_results, f, indent=4)

        return [], empty_cwe_report_results

    # Resolve SARIF locations using function resolver
    sarif_resolver = SarifResolver(codeql_cwe_sarif_report_path, func_resolver)
    sarif_resolved_results = sarif_resolver.get_results()

    # Only collect rules stats if requested
    if collect_rules_stats:
        rules_metadata = sarif_resolver.get_rules_metadata()
        error_rules_path = os.path.join(
            os.path.dirname(codeql_cwe_report_path), "error_rules.json"
        )
        rules_stats = collect_rules_stats_helper(rules_metadata, error_rules_path)
        _l.info(f"Rules stats: {rules_stats}")

    # Parse SARIF report and group by vulnerable functions
    vulnerable_functions = {}
    findings_per_rule_id = defaultdict(int)

    for result in sarif_resolved_results:
        try:
            # Extract basic vulnerability information
            rule_id = result.rule_id
            message = result.message
            description = result.sarif_rule.description if result.sarif_rule else ""
            short_description = (
                result.sarif_rule.short_description if result.sarif_rule else ""
            )
            tags = result.sarif_rule.tags if result.sarif_rule else []
            cwe_tags = [tag.split("/")[-1] for tag in tags if "cwe-" in tag]
            related_locations = result.related_locations

            # Check if rule is in allowlist - if so, apply default values and skip filtering
            is_in_allowlist = rule_id in ALLOWLIST_RULES

            if not is_in_allowlist:
                # Apply normal filtering for non-allowlisted rules
                if not cwe_tags:
                    _l.debug(
                        f"Skipping result with rule_id {rule_id} due to missing CWE tags"
                    )
                    continue

                if result.sarif_rule.severity != "error":
                    _l.debug(
                        f"Skipping result with rule_id {rule_id} due to problem.severity not being 'error'"
                    )
                    continue

                if result.sarif_rule.security_severity == "":
                    _l.debug(
                        f"Skipping result with rule_id {rule_id} due to missing security severity"
                    )
                    continue

            # Process each location in the result
            for location in result.locations:
                keyindex = location.keyindex
                start_line = location.region["startLine"]

                try:
                    # Extract code flow functions if available
                    code_flow_functions = {}
                    if hasattr(result, "codeflows") and result.codeflows:
                        for code_flow in result.codeflows:
                            flow_keyindices = {
                                flow_location.keyindex
                                for flow_location in code_flow.locations
                            }
                            code_flow_functions[code_flow.code_flow_id] = list(
                                flow_keyindices
                            )

                    # Extract related locations functions
                    related_locations_functions = []
                    for related_location in related_locations:
                        related_locations_functions.append(related_location.keyindex)

                    # Deduplicate related locations functions
                    related_locations_functions = list(set(related_locations_functions))

                    # Create vulnerability result entry
                    vuln_result = {
                        "rule_id": rule_id,
                        "message": message,
                        "description": description,
                        "short_description": short_description,
                        "start_line": start_line,
                        "cwe_tags": cwe_tags,
                        "severity": result.sarif_rule.severity,
                        "security_severity": result.sarif_rule.security_severity
                        if result.sarif_rule.security_severity != ""
                        else "0.0",
                        "code_flow_functions": code_flow_functions,
                        "related_locations_functions": related_locations_functions,
                    }

                    findings_per_rule_id[rule_id] += 1

                    # Group by function identifier
                    if keyindex not in vulnerable_functions:
                        vulnerable_functions[keyindex] = {"results": []}

                    vulnerable_functions[keyindex]["results"].append(vuln_result)

                except Exception as e:
                    _l.warning(f"Could not process location {location}: {e}")
                    continue

        except Exception as e:
            _l.warning(f"Could not process result: {e}")
            continue

    # Format the final results
    cwe_report_results = {
        "metadata": {
            "language": language,
            "total_vulnerable_functions": len(vulnerable_functions),
            "total_vulnerabilities": sum(
                len(func_data["results"]) for func_data in vulnerable_functions.values()
            ),
            "findings_per_rule_id": findings_per_rule_id,
        },
        "vulnerable_functions": vulnerable_functions,
    }

    # Save resolved report
    with open(codeql_cwe_report_path, "w") as f:
        json.dump(cwe_report_results, f, indent=4)

    return sarif_resolved_results, cwe_report_results


def collect_rules_stats_helper(rules_metadata, error_rules_path):
    """
    Collect rules statistics and save comprehensive rules data to JSON.
    Only triggered when --collect-rules-stats flag is provided.
    """
    total_rules = total_errors = total_warnings = 0
    error_rules = {}
    warning_rules = {}

    for rule_id, rule_metadata in rules_metadata.items():
        # Convert SarifRule object to JSON-serializable dictionary
        rule_dict = {
            "severity": rule_metadata.severity,
            "description": getattr(rule_metadata, "description", ""),
            "short_description": getattr(rule_metadata, "short_description", ""),
            "tags": getattr(rule_metadata, "tags", []),
            "security_severity": getattr(rule_metadata, "security_severity", ""),
        }

        if rule_metadata.severity == "error":
            total_errors += 1
            error_rules[rule_id] = rule_dict
        elif rule_metadata.severity == "warning":
            total_warnings += 1
            warning_rules[rule_id] = rule_dict

        total_rules += 1

    # Create comprehensive rules JSON with stats and rule lists
    comprehensive_rules_data = {
        "statistics": {
            "total_rules": total_rules,
            "total_errors": total_errors,
            "total_warnings": total_warnings,
        },
        "error_rules": error_rules,
        "warning_rules": warning_rules,
    }

    with open(error_rules_path, "w") as f:
        json.dump(comprehensive_rules_data, f, indent=4)

    return {
        "total_rules": total_rules,
        "total_errors": total_errors,
        "total_warnings": total_warnings,
    }


def main():
    parser = argparse.ArgumentParser(description="Run CWE queries on a CodeQL database")
    parser.add_argument(
        "--project-name",
        type=str,
        required=True,
        help="The name of the project in CodeQL database",
    )
    parser.add_argument(
        "--project-id",
        type=str,
        required=True,
        help="The ID of the project in CodeQL database",
    )
    parser.add_argument(
        "--full-functions-indices",
        type=str,
        required=True,
        help="Path to the full functions indices file",
    )
    parser.add_argument(
        "--functions-json-dir",
        type=str,
        required=True,
        help="Path to the functions JSON directory"
    )
    parser.add_argument(
        "--codeql-cwe-sarif-report",
        type=str,
        required=True,
        help="Output file path for the SARIF report",
    )
    parser.add_argument(
        "--codeql-cwe-report",
        type=str,
        required=True,
        help="Output file path for the resolved CWE report",
    )
    parser.add_argument(
        "--local-run", action="store_true", help="Run the analysis locally"
    )
    parser.add_argument(
        "--language",
        type=str,
        required=True,
        help="The language of the project (jvm or c)",
    )
    parser.add_argument(
        "--clear-existing-cwe-data",
        action="store_true",
        help="Clear existing CWE vulnerability data from analysis graph before uploading new data (default: False)",
    )
    parser.add_argument(
        "--skip-analysis-graph",
        action="store_true",
        help="Skip uploading results to analysis graph (default: False, meaning upload by default)",
    )
    parser.add_argument(
        "--collect-rules-stats",
        action="store_true",
        help="Collect rules stats (default: False)",
    )
    parser.add_argument(
        "--codeql-database-path",
        type=str,
        required=True,
        help="Path to the CodeQL database",
    )

    args = parser.parse_args()

    # Initialize function resolver
    try:
        if args.local_run:
            raise Exception("Local run requested")
        func_resolver = RemoteFunctionResolver(args.project_name, args.project_id)
        if not func_resolver.is_ready():
            raise Exception("RemoteFunctionResolver is not ready")
    except Exception as e:
        _l.warning(f"Using LocalFunctionResolver ({e})")
        func_resolver = LocalFunctionResolver(
            functions_index_path=str(args.full_functions_indices),
            functions_jsons_path=str(args.functions_json_dir),
        )

    # Run CWE analysis
    _, resolved_results = run_cwe_query(
        codeql_database_path=args.codeql_database_path,
        codeql_cwe_sarif_report_path=args.codeql_cwe_sarif_report,
        codeql_cwe_report_path=args.codeql_cwe_report,
        func_resolver=func_resolver,
        language=args.language,
        collect_rules_stats=args.collect_rules_stats,
    )

    # Upload to analysis graph only if requested
    if args.skip_analysis_graph:
        _l.info(
            "Skipping upload to analysis graph (--skip-analysis-graph flag provided)"
        )
    else:
        _l.info("Uploading results to analysis graph...")

        # Clean up existing CWE data only if requested
        if args.clear_existing_cwe_data:
            _l.info("Clear existing CWE data flag is enabled, cleaning up...")
            cleanup_existing_cwe_data()
        else:
            _l.info(
                "Preserving existing CWE data (use --clear-existing-cwe-data to clean up)"
            )

        upload_to_analysis_graph(resolved_results)
        _l.info("Upload to analysis graph completed successfully")


if __name__ == "__main__":
    main()