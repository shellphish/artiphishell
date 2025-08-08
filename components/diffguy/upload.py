"""
Main entry point for the CodeQL analyzer.
"""
import os
import sys
import logging
import argparse
import json

from typing import Dict, List, Any
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from config import DIFF_MODES, LANGUAGES, RUN_MODES
from core.project import Project
from core.diffAnalyzer import DiffAnalyzer
from core.utils import ensure_directories
from core.client import CodeQLWrapper

from analysis_graph.api import add_delta_info

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def parse_arguments():

    # Diff analysis command
    diff_parser = argparse.ArgumentParser(description='DiffGuy-Uploader')
    diff_parser.add_argument("--project_id", required=True, help="Project id")
    diff_parser.add_argument("--project_name", required=True, help="Project name")
    diff_parser.add_argument("--project_diff", required=True, help="Project diff")
    diff_parser.add_argument("--diff_data", required=True, help="Results of diff analysis")

    return diff_parser.parse_args()


def main():
    """Main entry point for the application."""
    args = parse_arguments()
    project_id = args.project_id
    project_name = args.project_name
    project_diff = args.project_diff
    diff_data = args.diff_data

    # Grab the diffguy_report.json in the diff_data directory
    diffguy_report_path = os.path.join(diff_data, project_name, "diffguy_report.json")
    if not os.path.exists(diffguy_report_path):
        logger.error(f"Diffguy report not found at {diffguy_report_path}")
        return
    with open(diffguy_report_path, "r") as f:
        diffguy_report = json.load(f)

    # Grab the boundaries
    function_diff = diffguy_report["function_diff"]
    boundary_diff = diffguy_report["boundary_diff"]

    # Read the project_diff as a binary string
    with open(project_diff, "rb") as f:
        project_diff_data = f.read()

    try:
        add_delta_info(
            project_id,
            project_diff_data,
            boundary_diff,
            function_diff
        )
    
        logger.info(f"Delta info added for project {project_id} to the analysis graph")
    except Exception as e:
        logger.error(f"Error while adding delta info to the analysis graph: {e}. Skipping...")
        return


if __name__ == "__main__":
    main()