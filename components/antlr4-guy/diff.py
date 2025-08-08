import argparse
import json
import filecmp
import shutil
from pathlib import Path


def find_files_only_in_target(base_dir, target_dir, output_dir, comparison_type):
    base = Path(base_dir) / comparison_type
    target = Path(target_dir) / comparison_type
    cmp = filecmp.dircmp(base, target)
    only_in_target = [target / f for f in cmp.right_only if (target / f).is_file()]
    save_location = output_dir / comparison_type
    save_location.mkdir(parents=True, exist_ok=True)
    for file_path in only_in_target:
        dest_path = save_location / file_path.name
        shutil.copy2(file_path, dest_path)
        print(f"Copied {file_path} -> {dest_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare two antler4-guy output files."
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        required=True,
        help="Base directory containing the original files.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        required=True,
        help="Target directory containing the modified files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to save the diff results.",
    )
    parser.add_argument(
        "--commit-id",
        type=str,
        required=True,
        help="Commit ID for the changes being compared.",
    )

    args = parser.parse_args()
    base_dir = args.base_dir
    target_dir = args.target_dir
    output_dir = args.output_dir
    commit_id = args.commit_id

    # Setup output directory structure
    output_dir = output_dir / f"1_{commit_id}"

    print(f"Comparing files in {base_dir} with {target_dir}...")

    find_files_only_in_target(base_dir, target_dir, output_dir, "METHOD")
    find_files_only_in_target(base_dir, target_dir, output_dir, "FUNCTION")
    find_files_only_in_target(base_dir, target_dir, output_dir, "CLASS")
    find_files_only_in_target(base_dir, target_dir, output_dir, "MACRO")


if __name__ == "__main__":
    main()
