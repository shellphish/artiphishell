from pathlib import Path
from loguru import logger
from unidiff import PatchSet
from collections import defaultdict


from .poi_poi import POI


class PatchPOI(POI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_poi(self, patch: Path):
        """Add a Point of Interest (POI) to the POI list.

        Args:
            patch (Path): The path to the patch file.
        """
        assert patch.is_file(), f"File {patch} does not exist."

        self.parse_poi_from_patch(patch)

    @staticmethod
    def is_c_or_cpp_file(file_path: str) -> bool:
        """Check if the file is a C or C++ file based on its extension."""
        return file_path.endswith((".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"))

    @staticmethod
    def is_java_file(file_path: str) -> bool:
        """"
        Check if the file is a Java file based on its extension
        """
        return file_path.endswith(".java")

    def get_funcindex_from_header(self, section_header: str, file_path: str, line_number: int) -> str | None:
        """
        Extract the function index key from the diff hunk
        """
        func_indices = []
        for index_key in self.local_function_resolver.find_by_filename(file_path):
            function_index = self.local_function_resolver.get(index_key)
            if function_index is None:
                continue
            if function_index.start_line <= line_number <= function_index.end_line:
                logger.trace(f"Found function index {index_key} for file {file_path} at line {line_number}")
                func_indices.append(index_key)

        logger.trace(f"Found {len(func_indices)} function indices for header: {section_header}")
        foo = filter(lambda x: file_path in x, func_indices)
        fixed_indices = list(
            set(self.local_function_resolver.find_matching_indices(list(foo), scope="focus")[0].values())
        )
        if len(fixed_indices) < 1:
            # If we don't find any function indices, we return None
            return None

        return fixed_indices[0]

    def parse_poi_from_patch(self, patch_file: Path) -> None:
        """Parse the patch to extract Points of Interest (POIs).

        Args:
            patch (Path): The path to the patch file.

        Returns:
            dict: A dictionary representing the POI extracted from the patch.
        """
        patchset = PatchSet.from_filename(patch_file)
        for patch in patchset:
            if not PatchPOI.is_c_or_cpp_file(patch.path) and not PatchPOI.is_java_file(patch.path):
                continue

            pois_within_file = defaultdict(str)
            for hunk in patch:
                logger.trace(f"Processing hunk in file {patch.path}: {hunk.section_header}")
                func_index = self.get_funcindex_from_header(hunk.section_header, patch.path, hunk.source_start)
                if func_index is None:
                    continue

                pois_within_file[func_index] += str(hunk)

            for thing in pois_within_file:
                logger.debug(f"Adding POI for function index {thing} with diff changes.")
                if len(self._pois) < 100:
                    self._pois.append(
                        {
                            "function_index_key": thing,
                            "file_name": patch.path,
                            "diff_changes": pois_within_file[thing],
                        }
                    )
                else:
                    logger.warning("😵 Maximum number of POIs reached. Skipping additional POIs.")
                    break
