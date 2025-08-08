"""
Main entry point for the CodeQL analyzer.
"""
import os
import sys
import logging
import argparse
from typing import Dict, List, Any
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agentlib
from agentlib import set_global_budget_limit
from config import DIFF_MODES, LANGUAGES, RUN_MODES
from core.project import Project
from core.diffAnalyzer import DiffAnalyzer
from core.utils import ensure_directories
from core.client import CodeQLWrapper
from crs_telemetry.utils import (
    get_otel_tracer,
    init_otel,
    init_llm_otel,
)
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

init_otel("diffguy", "program_analysis", "diff_analysis")
init_llm_otel()
tracer = get_otel_tracer()

def parse_arguments():

    # Diff analysis command
    diff_parser = argparse.ArgumentParser(description='DiffGuy')
    diff_parser.add_argument("--name", required=True, help="Project name")
    diff_parser.add_argument("--language", required=True, choices=LANGUAGES, help="Project language")
    diff_parser.add_argument("--id-before", required=True, help="Project ID before diff applies")
    diff_parser.add_argument("--id-after", required=True, help="Project ID after diff applies")
    diff_parser.add_argument("--query-path", required=True, help="Path to query files")
    diff_parser.add_argument("--save-path", required=True, help="Path to save results")
    diff_parser.add_argument("--diff-mode", choices=DIFF_MODES, default="all", help="Diff mode (default: all)")
    diff_parser.add_argument("--run-mode", choices=RUN_MODES, default="remote",
                            help="Run mode (default: remote)")

    return diff_parser.parse_args()


def run_diff_analysis(args):
    """Run differential analysis between two projects."""
    logger.info(f"Starting diff analysis for {args.name} in {args.diff_mode} mode")

    # Ensure save directory exists
    ensure_directories(args.save_path)

    # Create and run the diff analyzer
    diff_analyzer = DiffAnalyzer(
        args.name,
        args.language,
        args.id_before,
        args.id_after,
        args.query_path,
        args.save_path,
        args.diff_mode,
        args.run_mode
    )

    diff_analyzer.run()

    logger.info(f"Diff analysis completed for {args.name}")

def main():

    """Main entry point for the application."""
    args = parse_arguments()
    if args.run_mode == "remote":
        run_diff_analysis(args)
    elif args.run_mode == "local":
        # try:
        #     c1 = CodeQLWrapper(args.name, args.id_before, args.language)
        #     codeql_db_path = os.environ.get("CODEQL_DB_PATH")
        #     c1.upload_database(codeql_db_path)

        #     c2 = CodeQLWrapper(args.name, args.id_after, args.language)
        #     codeql_base_db_path = os.environ.get("CODEQL_BASE_DB_PATH")
        #     c2.upload_database(codeql_base_db_path)

        # except Exception as e:
        #     pass
        run_diff_analysis(args)

if __name__ == "__main__":
    agentlib.enable_event_dumping("/tmp/stats/")
    with tracer.start_as_current_span("diffguy.main"):
        main()