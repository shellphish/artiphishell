from pathlib import Path
from loguru import logger
from typing import Generator

from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.function_resolver import (
    LocalFunctionResolver,
    RemoteFunctionResolver,
    FunctionResolver,
    function_index_to_source_location,
)


class POI(object):
    def __init__(
        self,
        full_function_indices_path: Path,
        target_functions_json_dir: Path,
        project_id: str | None = None,
        project_name: str | None = None,
        function_resolver: FunctionResolver | None = None,
    ):
        """Initialize the POI object with the function indices and target functions info.

        Args:
            full_function_indices_path (Path): The path to the full function indices JSON file.
            target_functions_json_dir (Path): The directory containing target functions JSON files.
        """
        self._pois: list = []
        self.project_id: str | None = project_id
        self.project_name: str | None = project_name
        self.full_function_indices: Path = full_function_indices_path
        self.target_functions_json_dir: Path = target_functions_json_dir

        self.function_resolver = None
        self._local_function_resolver = None

        if function_resolver is not None:
            self.function_resolver = function_resolver
        else:
            self._setup_func_resolver(project_id, project_name, full_function_indices_path, target_functions_json_dir)

    def _setup_func_resolver(
        self, project_id, project_name, full_function_indices: Path, target_functions_json_dir: Path
    ):
        if project_id is not None and project_name is not None:
            logger.debug(f"Using RemoteFunctionResolver for project {project_name} ({project_id})")
            self.function_resolver = RemoteFunctionResolver(
                cp_name=project_name,
                project_id=project_id,
            )
        else:
            assert full_function_indices.is_file(), f"File {full_function_indices} does not exist."
            assert target_functions_json_dir.is_dir(), f"Directory {target_functions_json_dir} does not exist."
            logger.debug(
                f"Using LocalFunctionResolver with indices at {full_function_indices} and functions at {target_functions_json_dir}"
            )
            self.function_resolver = LocalFunctionResolver(
                functions_index_path=str(full_function_indices),
                functions_jsons_path=str(target_functions_json_dir),
            )
            self._local_function_resolver = self.function_resolver

    def _setup_local_function_resolver(self):
        if self._local_function_resolver is not None:
            logger.debug("Using existing LocalFunctionResolver")
            return
        assert self.full_function_indices.is_file(), f"File {self.full_function_indices} does not exist."
        assert self.target_functions_json_dir.is_dir(), f"Directory {self.target_functions_json_dir} does not exist."
        logger.debug(
            f"Using LocalFunctionResolver with indices at {self.full_function_indices} and functions at {self.target_functions_json_dir}"
        )
        self._local_function_resolver = LocalFunctionResolver(
            functions_index_path=str(self.full_function_indices),
            functions_jsons_path=str(self.target_functions_json_dir),
        )

    @property
    def empty(self) -> bool:
        return len(self._pois) == 0

    def add_poi(self, poi: dict):
        raise NotImplementedError("This method should be implemented in a subclass.")

    def remove_all_pois(self):
        self._pois = []

    def get_next_poi(self) -> Generator[dict, None, None]:
        for poi in self._pois:
            yield poi

    def get_all_pois(self) -> list:
        """
        A function that retrieves all POIs.

        Returns:
            list: A list of all POIs.
        """
        return self._pois

    def get_function_index_from_poi(self, function_index_str: str) -> FunctionIndex:
        """
        A function that retrieves the function index from a given string.

        Args:
            function_index_str (str): The function index string.

        Returns:
            FunctionIndex: The function index object.
        """
        try:
            resolved_function_index_key = self.function_resolver.find_matching_index(
                function_index_str,
                scope="focus",
                can_include_self=False,
                can_include_build_generated=False,
            )
        except:
            logger.warning(f"Could not resolve function index key for {function_index_str}")
            if not isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                resolved_function_index_key = self._local_function_resolver.find_matching_index(
                    function_index_str,
                    scope="focus",
                    can_include_self=False,
                    can_include_build_generated=False,
                )

        if resolved_function_index_key is not None:
            try:
                resolved_function_index = self.function_resolver.get(resolved_function_index_key)
            except:
                logger.warning(f"Could not resolve function index key {resolved_function_index_key}")
                if not isinstance(self.function_resolver, RemoteFunctionResolver):
                    logger.info("Retrying with local function resolver")
                    self._setup_local_function_resolver()
                    resolved_function_index = self._local_function_resolver.get(resolved_function_index_key)
            logger.debug(f"Using function index key: {resolved_function_index_key}")
            logger.debug(f"{resolved_function_index.is_generated_during_build=}")
            return resolved_function_index

        logger.debug(f"Finding source locations from function index key: {function_index_str}")
        try:
            resolved_function_index = self.function_resolver.get(function_index_str)
        except:
            logger.warning(f"Could not resolve function index key {function_index_str}")
            if isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                resolved_function_index = self._local_function_resolver.get(function_index_str)
        src_location = function_index_to_source_location(function_index_str, resolved_function_index)
        try:
            candidates = self.function_resolver.resolve_source_location(
                src_location,
                num_top_matches=3,
                allow_build_generated=False,
                focus_repo_only=True,
            )
        except:
            logger.warning(f"Could not resolve source location for {src_location}")
            if isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                candidates = self._local_function_resolver.resolve_source_location(
                    src_location,
                    num_top_matches=3,
                    allow_build_generated=False,
                    focus_repo_only=True,
                )
        if not candidates:
            logger.warning(f"Could not resolve function index for {function_index_str}")
            raise ValueError(f"Function index {function_index_str} could not be resolved.")
        try:
            actual_key = candidates[0][0]
        except IndexError:
            logger.warning(f"Could not resolve function index for {function_index_str}")
            raise ValueError(f"Function index {function_index_str} could not be resolved.")
        logger.debug(f"Resolved function index {function_index_str} to {actual_key}")
        ret_val = None
        try:
            ret_val = self.function_resolver.get(actual_key)
        except:
            logger.warning(f"Could not resolve function index key {actual_key}")
            if isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                ret_val = self._local_function_resolver.get(actual_key)
        return ret_val

    def funcindex_to_ag_funcindex(self, name: str) -> str:
        # TODO: non-focus -> compiled in the near future
        ag_index = None
        try:
            ag_index = self.function_resolver.find_matching_index(name, scope="non-focus")
        except:
            logger.warning(f"Could not resolve function index for {name}")
            if not isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                ag_index = self._local_function_resolver.find_matching_index(name, scope="non-focus")
        if ag_index is None:
            raise ValueError(f"😭 Function index not found for {name}")
        return ag_index

    def ag_funcindex_to_funcindex(self, name: str) -> str:
        ag_index = None
        try:
            ag_index = self.function_resolver.find_matching_index(name, scope="focus")
        except:
            logger.warning(f"Could not resolve function index for {name}")
            if not isinstance(self.function_resolver, RemoteFunctionResolver):
                logger.info("Retrying with local function resolver")
                self._setup_local_function_resolver()
                ag_index = self._local_function_resolver.find_matching_index(name, scope="focus")
        if ag_index is None:
            raise ValueError(f"😩 Function index not found for {name}")
        return ag_index
