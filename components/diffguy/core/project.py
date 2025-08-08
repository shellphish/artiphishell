"""
Project class for CodeQL analysis.
"""
import os
import logging
from typing import Dict, List, Any, Optional
from tqdm import tqdm
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import QUERY_PATHS, FILE_TEMPLATES
from core.client import CodeQLWrapper
from core.utils import save_json, load_json, ensure_directories, group_vulnerabilities_by_function, reformat_boundary

# Configure logging
logger = logging.getLogger(__name__)

class Project:
    """A class representing a CodeQL project for analysis."""

    def __init__(self, project: str, version:str, project_id: str, language:str, query_path: str, save_path: str):

        self.project = project
        self.project_name = project + "_" + version
        self.project_id = project_id
        self.language = language
        self.client = CodeQLWrapper(self.project, self.project_id, self.language)

        self.query_dir = os.path.join(query_path, QUERY_PATHS["vuln_query"])
        self.input_boundary_query_path = os.path.join(query_path, QUERY_PATHS["input_boundary"])
        # self.sink_boundary_query_path = os.path.join(query_path, QUERY_PATHS["sink_boundary"]) ## NOT IN USE

        self.save_path = save_path
        ensure_directories(self.save_path)

        self.vuln_save_path = os.path.join(
            self.save_path,
            FILE_TEMPLATES["vulns_result"].format(project_name=self.project_name)
        )
        self.boundary_save_path = os.path.join(
            self.save_path,
            FILE_TEMPLATES["boundary_result"].format(project_name=self.project_name)
        )
        self.sanitizers = []
        self.init_project()


    def init_project(self):
        if os.path.exists(self.vuln_save_path):
            logger.debug(f"Vulnerability results already exist, loading from file")
            self.vulns_result = load_json(self.vuln_save_path)
        else:
            self.vulns_result = self.analyze_function()

        if os.path.exists(self.boundary_save_path):
            logger.debug(f"Boundary results already exist, loading from file")
            self.input_boundary = load_json(self.boundary_save_path)
        else:
            self.input_boundary = self.analyze_input_boundary()



    def analyze_function(self) -> Dict[str, List[Dict[str, Any]]]:
        logger.info(f"Analyzing vulnerabilities for project {self.project_name}")
        # Get all query files
        files = os.listdir(self.query_dir)
        # Execute each query
        results = {}
        for file in tqdm(files, desc=f"Running vulnerability CodeQL queries for {self.project_name}"):
            query_name = file.split(".")[0]
            query_path = os.path.join(self.query_dir, file)

            # Path to save individual query results
            result_path = os.path.join(
                self.save_path,
                FILE_TEMPLATES["query_result"].format(
                    query_name=query_name,
                    project_name=self.project_name
                )
            )

            # Skip if results already exist
            if os.path.exists(result_path):
                logger.debug(f"[+] {query_name} exists: Loading from file")
                with open(query_path) as f:
                    query = f.read()
                result = load_json(result_path)
            else:
                logger.debug(f"[+] {query_name} not exists: Querying to CodeQL")
                with open(query_path) as f:
                    query = f.read()
                result = self.client.execute_query(query)
                save_json(result_path, result)
            if result is None:
                logger.error(f"Error executing query {query_name} for project {self.project_name}")
                continue
            self.sanitizers.append(query_name)
            results[query_name] = result
        reformat_results = group_vulnerabilities_by_function(results)
        save_json(self.vuln_save_path, reformat_results)
        return reformat_results

    def analyze_input_boundary(self) -> List[Dict[str, Any]]:
        logger.info(f"Analyzing input boundaries for project {self.project_name}")
        with open(self.input_boundary_query_path) as f:
            query = f.read()
        result = self.client.execute_query(query)
        if result is None:
            logger.error(f"Error executing input boundary query for project {self.project_name}")
            reformat_results = None
        else:
            reformat_results = reformat_boundary(result)
        save_json(self.boundary_save_path, reformat_results)
        return reformat_results
