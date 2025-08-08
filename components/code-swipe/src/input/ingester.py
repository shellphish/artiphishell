"""Function index ingester."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
from pydantic import Field

from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver, FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from src.input.code_registry import CodeRegistry
from src.models.code_block import CodeBlock
from src.common.util import time_it

logger = logging.getLogger(__name__)

USE_REMOTE_FUNCTION_RESOLVER = True

class FunctionIndexIngester(ShellphishBaseModel):
    """Ingests function index files and creates CodeBlock instances."""

    code_registry: CodeRegistry = Field(default_factory=CodeRegistry)

    index_dir: Path = Field(
        description="Directory containing function index files"
    )
    index_dir_json: Path = Field(
        description="Directory containing function index JSON files"
    )

    __RESOLVER__: Optional[FunctionResolver] = None

    def get_resolver(self, project: OSSFuzzProject) -> Optional[FunctionResolver]:
        if FunctionIndexIngester.__RESOLVER__:
            return FunctionIndexIngester.__RESOLVER__

        if project is None:
            return None

        use_local_instead = not USE_REMOTE_FUNCTION_RESOLVER

        if USE_REMOTE_FUNCTION_RESOLVER:
            resolver = RemoteFunctionResolver(
                cp_name=project.project_name,
                project_id=project.project_id
            )
            if not resolver.is_ready():
                logger.warning(f"Remote function resolver is not ready! Using local resolver instead.")
                use_local_instead = True

        if self.index_dir and self.index_dir_json and use_local_instead:
            resolver = LocalFunctionResolver(
                functions_index_path=self.index_dir,
                functions_jsons_path=self.index_dir_json
            )

        FunctionIndexIngester.__RESOLVER__ = resolver
        return resolver

    @time_it
    def get_all_functions_via_resolver(self, project: OSSFuzzProject) -> Dict[str, FunctionIndex]:
        """Ingest function index files via the function resolver."""

        resolver = self.get_resolver(project)

        res = resolver.get_filtered('true', '.value.focus_repo_relative_path != null')
        # Sometimes can resturn a list of IDS instead????
        if isinstance(res, list):
            res = {k: resolver.get(k) for k in res}


        assert len(res) > 0, "No functions found"

        logger.info(f"Found {len(res)} functions")
        logger.info(f"First function: {next(iter(res.items()))}")
        return res

    @time_it
    def get_inscope_function_keys(self, project: OSSFuzzProject) -> set[str]:
        resolver = self.get_resolver(project)

        focus_repo_path = project.get_focus_repo_container_path()
        res = resolver.get_focus_repo_keys(focus_repo_path)

        assert len(res) > 0, "No in-scope function keys found"

        logger.info(f"Found {len(res)} in-scope function keys")
        logger.info(f"First in-scope function key: {res[0]}")

        return set(res)

    def load_function_index(self, file_path: Path) -> FunctionIndex:
        """Load a single function index file.

        Args:
            file_path: Path to the function index JSON file

        Returns:
            FunctionIndex instance
        """
        logger.debug(f"Loading function index from {file_path}")
        try:
            with open(file_path) as f:
                data = json.load(f)
                logger.debug(f"Successfully loaded JSON from {file_path}")
                index = FunctionIndex.model_validate(data)
                logger.debug(f"Successfully validated function index for {index.funcname}")
                return index
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load function index from {file_path}: {e}")
            raise

    @time_it
    def ingest_directory(self, project: OSSFuzzProject) -> None:
        """Ingest all function index files from a directory.

        Returns:
            List of CodeBlock instances
        """
        logger.info(f"Starting ingestion from {self.index_dir_json}")

        all_funcs = self.get_all_functions_via_resolver(project)
        if len(all_funcs) == 0:
            logger.error("No functions found")
            return

        code_blocks = []

        # Recursively find all JSON files
        for func_key, function_index in all_funcs.items():
            logger.debug(f"Found function: {func_key}")
            try:
                code_block = CodeBlock(function_key=func_key, function_info=function_index)

                logger.debug(f"Created code block for function: {code_block.function_info.funcname}")
                code_blocks.append(code_block)
            except Exception as e:
                logger.error(f"Error processing {func_key}: {e}")
                continue

        logger.info(f"Completed ingestion. Found {len(code_blocks)} code blocks")

        self.code_registry.add_code_blocks(code_blocks)