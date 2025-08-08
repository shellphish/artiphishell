import sys
import shutil
import argparse
from pathlib import Path
from loguru import logger
from tempfile import mkdtemp
from tempfile import NamedTemporaryFile

from aijon_lib import (
    ag_utils,
    find_error_locations,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Try and fix compiler errors with LLM."
    )
    parser.add_argument(
        "--target_source",
        type=Path,
        required=True,
        help="Path to the target source directory.",
    )
    parser.add_argument(
        "--stderr_log",
        type=Path,
        required=True,
        help="Path to the stderr log file from oss-fuzz-build.",
    )
    parser.add_argument(
        "--patch_path",
        type=Path,
        required=True,
        help="Path to the file containing the diff.",
    )
    parser.add_argument(
        "--destination",
        "-d",
        type=Path,
        required=False,
        help="The path to store the output.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    target_source = args.target_source
    stderr_file = args.stderr_log
    patch_path = args.patch_path

    if not target_source.is_dir():
        logger.error(f"Target source directory {target_source} does not exist.")
        exit(1)
    if not stderr_file.is_file():
        logger.error(f"Stderr file {stderr_file} does not exist.")
        exit(1)
    if not patch_path.is_file():
        logger.error(f"Applied diff file {patch_path} does not exist.")
        exit(1)

    if args.destination:
        destination = args.destination
        if not destination.is_dir():
            logger.info(f"🔮 Creating directory {destination}.")
            destination.mkdir(parents=True, exist_ok=True)
    else:
        tempdir = mkdtemp()
        destination = Path(tempdir)

    with open(stderr_file, "r") as f:
        compiler_error_str = f.read()

    temp_dir = mkdtemp()
    modified_source_dir = Path(temp_dir)
    shutil.copytree(target_source, modified_source_dir, dirs_exist_ok=True)

    logger.info(f"🪛 Applying patch {patch_path} to source @ {modified_source_dir}")
    ag_utils.apply_diff(modified_source=modified_source_dir, patch_path=patch_path)

    logger.info("🗑️ Yeeting hunks that cause errors.")
    location_infos: list[int] = find_error_locations(
        compiler_error_str=compiler_error_str,
        applied_diff=patch_path.read_text(),
    )
    diff_lines = patch_path.read_text().splitlines()
    for patch_id in location_infos:
        for idx, line in enumerate(diff_lines):
            if f"/* PATCHID:{patch_id} */" in line:
                logger.debug(f"Yeeting line {idx}: {line} for patch ID {patch_id}")
                diff_lines[idx] = "+"

    new_diff_contents = "\n".join(diff_lines)
    with NamedTemporaryFile(mode="w+", delete=True) as temp_patch_file:
        temp_patch_path = Path(temp_patch_file.name)
        temp_patch_path.write_text(new_diff_contents + "\n")
        logger.info("Reversing the old patch")
        _ = ag_utils.get_diff_contents(
            modified_source=modified_source_dir,
            reset=True,
        )
        logger.info("Applying the new patch")
        ag_utils.apply_diff(
            modified_source=modified_source_dir,
            patch_path=temp_patch_path,
            allow_rejections=False,
        )
    logger.success("🎉 Successfully yeeted PATCHID that cause errors.")

    logger.info(f"🔎 Getting diff contents from source @ {modified_source_dir}.")
    diff_contents = ag_utils.get_diff_contents(modified_source_dir)
    diff_file = destination / "aijon_instrumentation.patch"
    if len(diff_contents) == 0:
        raise ValueError("☣️ Nothing to diff.️")
    else:
        logger.trace(f"Diff contents: \n{diff_contents}")
        diff_file.write_text(diff_contents)
        logger.success(f"🎀 Diff file is saved to {diff_file}.")

    shutil.rmtree(modified_source_dir)
