import shutil
from pathlib import Path
from loguru import logger
from tempfile import NamedTemporaryFile, TemporaryDirectory

from shellphish_crs_utils.function_resolver import FunctionResolver

from .poi_interface import (
    PatchPOI,
    SarifPOI,
    CodeSwipePOI,
)
from .llm_interface import (
    instrument_code_with_ijon,
    apply_llm_response,
    find_error_locations,
)
from .ag_interface import utils as ag_utils


def annotate_from_patch(
    patch_file: Path,
    source_code_dir: Path,
    function_resolver: FunctionResolver,
    language=None,
) -> Path:
    """Annotate source code from a patch file.

    Args:
        patch_file (Path): The path to the patch file.
        source_code_dir (Path): The directory containing the source code.
        function_resolver (FunctionResolver): The function resolver to use.

    Returns:
        Path: The path to the new diff file with annotations.
    """
    patch_poi = PatchPOI(function_resolver=function_resolver)
    patch_poi.add_poi(patch_file)
    assert patch_poi.empty is False, "No POIs found in the patch file."

    with TemporaryDirectory() as temp_dir:
        modified_source_code_dir = Path(temp_dir)
        shutil.copytree(source_code_dir, modified_source_code_dir, dirs_exist_ok=True)
        ag_utils.apply_diff(modified_source_code_dir, patch_file)

        total_cost = 0.0
        for poi in patch_poi.get_next_poi():
            logger.info(f"Processing POI: {poi['function_index_key']}")
            resolved_sinkfunc_index = patch_poi.get_function_index_from_poi(poi["function_index_key"])
            cost, llm_response = instrument_code_with_ijon(
                poi=poi,
                function_index=resolved_sinkfunc_index,
                modified_source_dir=modified_source_code_dir,
                write_out=True,
                language=language,
            )
            total_cost += cost

        logger.info(f"Total cost for annotating patch: {total_cost}")
        diff_contents = ag_utils.get_diff_contents(modified_source_code_dir)
        logger.info(f"Updated diff contents:\n{diff_contents}")

    new_diff_file = Path(NamedTemporaryFile(mode="w", delete=False, suffix=".patch").name)
    new_diff_file.write_text(diff_contents)
    return new_diff_file
