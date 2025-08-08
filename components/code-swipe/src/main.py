"""Main entry point for code-swipe component."""

import argparse
import logging
import sys
import yaml

from pathlib import Path
from typing import List, Optional
from pydantic import Field

# Add src directory to path so we can use absolute imports
src_dir = Path(__file__).parent.parent
sys.path.append(str(src_dir))

from src.input.ingester import FunctionIndexIngester
from src.input.code_registry import CodeRegistry

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from src.models import BaseObject
from src.models.filter import FilterPass
from src.framework.filter_framework import FilterFramework
from shellphish_crs_utils.models.ranking import RankedFunction, CodeSwipeRanking
from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
)

init_otel("code-swipe", "static_analysis", "code_swipe")
tracer = get_otel_tracer()

logger = logging.getLogger(__name__)


def setup_logging(debug: bool = False) -> None:
    """Set up logging configuration.

    Args:
        debug: Whether to enable debug logging
    """
    level = logging.DEBUG if debug else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Suppress noisy loggers
    logging.getLogger("pydantic").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Code Swipe - Code filtering and prioritization"
    )

    parser.add_argument("--project-metadata-path", required=True, type=Path)
    parser.add_argument("--project-id", required=True, type=str)
    parser.add_argument("--project-dir", required=True, type=Path)
    parser.add_argument("--diffguy-report-dir", required=False, type=Path)
    parser.add_argument("--codeql-report", required=False, type=Path)
    parser.add_argument("--semgrep-report-path", required=False, type=Path)
    parser.add_argument("--semgrep-report-base-path", required=False, type=Path)
    parser.add_argument("--codeql-cwe-report", required=False, type=Path)
    parser.add_argument("--codeql-cwe-report-base-path", required=False, type=Path)
    parser.add_argument("--scanguy-results-path", required=False, type=Path)
    parser.add_argument("--commit-functions-index", required=False, type=Path)
    parser.add_argument("--commit-functions-json", required=False, type=Path)

    parser.add_argument(
        "--index-dir",
        type=Path,
        required=True,
        help="Directory containing function index files",
    )

    parser.add_argument(
        "--index-dir-json",
        type=Path,
        required=True,
        help="Directory containing function index files",
    )
    parser.add_argument(
        "--output-path", type=Path, required=False, help="Path to output the ranking"
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser.parse_args()


class Main(BaseObject):
    model_config = {
        "arbitrary_types_allowed": True,
        "extra": "forbid",  # Preserve parent config
    }

    args: argparse.Namespace = Field(exclude=True)

    project: Optional[OSSFuzzProject] = None

    filter_framework: Optional[FilterFramework] = None
    code_registry: Optional[CodeRegistry] = None

    def preprocess(self) -> None:
        with open(self.args.project_metadata_path) as f:
            augmented_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        print(self.args.project_dir)

        project = OSSFuzzProject(
            self.args.project_dir,
            project_id=self.args.project_id,
            augmented_metadata=augmented_metadata,
        )
        self.project = project

        self.register_filters()

        self.info(f"Starting Code Swipe on {project.project_name}")

        code_registry = CodeRegistry(
            index_dir=self.args.index_dir, index_dir_json=self.args.index_dir_json
        )
        self.code_registry = code_registry

        # Create ingester
        ingester = FunctionIndexIngester(
            index_dir=self.args.index_dir,
            index_dir_json=self.args.index_dir_json,
            code_registry=code_registry,
        )

        # Load code blocks
        self.info("Starting code block ingestion")
        ingester.ingest_directory(project)

        #ingester.ingest_via_function_resolver(project)
        ingester.get_inscope_function_keys(project)

        metadata = {}

        code_registry.pre_process_project(project, metadata)
        self.info(
            f"Successfully loaded {len(code_registry.all_code_blocks)} code blocks"
        )
        #if self.__LOGGER__.isEnabledFor(logging.DEBUG):
        #    for block in code_registry.all_code_blocks:
        #        self.debug(f"Loaded function: {block.function_info.funcname}")

        self.filter_framework.pre_process_project(project, code_registry, metadata)

    def initialize(self) -> None:
        self.filter_framework = FilterFramework()

    def run(self) -> None:
        """Main entry point."""
        try:
            setup_logging(self.args.debug)

            self.initialize()

            self.preprocess()

            self.process()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.output_backup_results()

    def process(self) -> None:
        self.filter_framework.process_project(self.project, self.code_registry, {})
        self.output_results()
        self.print_top_results()

    def output_results(self) -> None:
        # Get all blocks and sort by priority score
        blocks = list(self.code_registry.all_code_blocks)
        blocks.sort(key=lambda x: x.priority_score, reverse=True)

        ranking = []

        for i, block in enumerate(blocks):
            if block.priority_score is None or block.priority_score <= 0.0:
                continue

            ranked_function = RankedFunction.from_function_index(
                block.function_info,
                function_index_key=block.function_key,
                priority_score=block.priority_score,
                metadata=block.metadata,
                rank_index=i,
                weights={k: v.weight for k, v in block.filter_results.items()},
            )
            ranking.append(ranked_function)

        res = CodeSwipeRanking(ranking=ranking)

        output_file = self.args.output_path
        if output_file:
            model_yaml = yaml.safe_dump(res.model_dump())

            with open(str(output_file), "w") as f:
                f.write(model_yaml)

    def output_backup_results(self) -> None:
        # If we failed, we need to output a simple results file with no entries, just so we don't block any downstream tasks
        output_file = self.args.output_path
        if output_file:
            res = CodeSwipeRanking(ranking=[])
            model_yaml = yaml.safe_dump(res.model_dump())

            with open(str(output_file), "w") as f:
                f.write(model_yaml)

    def print_top_results(self, top_n: int = 20) -> None:
        """Print the top N scored code blocks.

        Args:
            top_n: Number of top results to print
        """
        self.info(f"\nTop {top_n} Scored Functions:")
        self.info("-" * 80)

        # Get all blocks and sort by priority score
        blocks = list(self.code_registry.all_code_blocks)
        blocks.sort(key=lambda x: x.priority_score, reverse=True)

        # Print top N results
        for i, block in enumerate(blocks[:top_n], 1):
            self.info(
                f"{i}. Score: {block.priority_score:.2f} - Function: {block.function_info.funcname}"
            )
            if block.function_info.focus_repo_relative_path:
                self.info(f"   File: {block.function_info.focus_repo_relative_path}")
            elif block.function_info.target_container_path:
                self.info(f"   File: {block.function_info.target_container_path}")
            elif block.function_info.filename:
                self.info(f"   File: {block.function_info.filename}")

            if block.metadata:
                self.info(f"   Metadata: {block.metadata}")
            self.info("")

    def register_filters(self) -> None:
        for filter_pass in self.get_enabled_filters():
            self.filter_framework.register_pass(filter_pass)

    def get_enabled_filters(self) -> List[FilterPass]:
        # NOTE:
        # Ordering here is the order that filters will be executed.


        filters = []

        try:
            from src.filters.diff_baseline import DiffBaselineFilter
            if self.args.commit_functions_index and self.args.commit_functions_json:
                filters += [DiffBaselineFilter(
                    changed_functions_index_path=str(self.args.commit_functions_index),
                    changed_functions_jsons_dir=str(self.args.commit_functions_json)
                )]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering DiffBaseline filter: {e}")

        try:
            from src.filters.diffguy import DiffguyFilter
            if self.args.diffguy_report_dir:
                filters += [DiffguyFilter.from_report(self.args.diffguy_report_dir)]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering Diffguy filter: {e}")

        try:
            from src.filters.semgrep import SemgrepFilter
            if self.args.semgrep_report_path:
                semgrep_filter = SemgrepFilter.from_report(
                    self.args.semgrep_report_path, weight_mode="vuln_type" # we can choose from different weight modes
                )
                semgrep_filter.name = "Semgrep"  # Main Semgrep filter
                filters += [semgrep_filter]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering Semgrep filter: {e}")

        try:
            from src.filters.semgrep import SemgrepFilter
            if self.args.semgrep_report_base_path:
                semgrep_base_filter = SemgrepFilter.from_report(
                    self.args.semgrep_report_base_path, weight_mode="vuln_type", is_negative=True
                )
                semgrep_base_filter.name = "Semgrep_base"  # Different name for base filter
                filters += [semgrep_base_filter]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering Semgrep base filter: {e}")

        try:
            from src.filters.codeql import CodeQLFilter
            if self.args.codeql_report:
                filters += [CodeQLFilter.from_report(self.args.codeql_report, language=self.project.project_language)]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering CodeQL filter: {e}")

        try:
            from src.filters.codeql_cwe import CodeqlCWEFilter
            if self.args.codeql_cwe_report:
                cwe_filter = CodeqlCWEFilter.from_report(
                    self.args.codeql_cwe_report, language=self.project.project_language, weight_mode="combined"
                )
                cwe_filter.name = "CodeqlCWE"  # Main CWE filter
                filters += [cwe_filter]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering CodeQL CWE filter: {e}")

        try:
            from src.filters.codeql_cwe import CodeqlCWEFilter
            if self.args.codeql_cwe_report_base_path:
                cwe_base_filter = CodeqlCWEFilter.from_report(
                    self.args.codeql_cwe_report_base_path, language=self.project.project_language, weight_mode="combined", is_negative=True
                )
                cwe_base_filter.name = "CodeqlCWE_base"  # Different name for base filter
                filters += [cwe_base_filter]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering CodeQL CWE base filter: {e}")

        try:
            from src.filters.scanguy import ScanGuyFilter
            if self.args.scanguy_results_path:
                filters += [
                    ScanGuyFilter.from_report(
                        self.args.scanguy_results_path, language=self.project.project_language
                    )
                ]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering ScanGuy filter: {e}")
        # NOTE:
        # Ordering here is the order that filters will be executed.

        try:
            from src.filters.static_reachability import SimpleReachabilityFilter
            filters += [SimpleReachabilityFilter()]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering SimpleReachability filter: {e}")

        try:
            from src.filters.dangerous_functions import DangerousFunctionsFilter
            filters += [DangerousFunctionsFilter(language=self.project.project_language)]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering DangerousFunctions filter: {e}")

        try:
            from src.filters.dynamic_reachability import DynamicReachabilityFilter
            filters += [DynamicReachabilityFilter()]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering DynamicReachability filter: {e}")

        try:
            from src.filters.skip_tests import SkipTestsFilter
            filters += [SkipTestsFilter()]
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error registering SkipTests filter: {e}")


        return filters


def main() -> None:
    args = parse_args()
    Main(args=args).run()


if __name__ == "__main__":
    with tracer.start_as_current_span("code_swipe") as span:
        main()
        span.set_status(status_ok())
