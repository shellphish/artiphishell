"""
Wrapper around the CodeQLClient.
"""
import logging
import os
from typing import Dict, Any, List, Optional

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CODEQL_SERVER_URL

# Set environment variable for CodeQL server URL
os.environ["CODEQL_SERVER_URL"] = CODEQL_SERVER_URL
from libcodeql.client import CodeQLClient

# Configure logging
logger = logging.getLogger(__name__)

class CodeQLWrapper:
    """Wrapper around the CodeQLClient for easier use."""

    def __init__(self, project_name: str, project_id: str, language: str):
        """Initialize the CodeQLClient."""
        self.client = CodeQLClient(timeout=60)
        self.project_name = project_name
        self.language = language
        self.project_id = project_id

    def upload_database(self, db_path: str) -> str:
        try:
            res = self.client.upload_db(self.project_name, self.project_id, self.language, db_path)
            logger.debug(f"Database uploaded for project {self.project_name}")
            return res
        except Exception as e:
            logger.error(f"Error uploading database for project {self.project_name}: {e}")
            raise Exception(f"Database upload failed for project {self.project_name}: {str(e)}") from e


    def execute_query(self,  query: str):
        try:
            result = self.client.query({
                "cp_name": self.project_name,
                "project_id": self.project_id,
                "query": query
            })
            logger.debug(f"Query executed successfully for project {self.project_name}")
            return result
        except Exception as e:
            logger.error(f"Error executing query for project {self.project_name}: {e}")
            return None