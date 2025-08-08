import shutil
import json
from argparse import ArgumentParser
from pathlib import Path

parser = ArgumentParser()
parser.add_argument("--base-dir", type=Path, required=True)
parser.add_argument("--head-dir", type=Path, required=True)
parser.add_argument("--out-dir", type=Path, required=True)
parser.add_argument("--commit-hash", type=str, required=True)
parser.add_argument("--base-compile-commands", type=Path, required=True)

args = parser.parse_args()


def get_files(directory: Path):
    files = {}
    for subdir in directory.iterdir():
        if subdir.is_dir():
            files[subdir.name] = {file.name for file in subdir.glob("*.json")}
    return files


base_files = get_files(args.base_dir)
head_files = get_files(args.head_dir)

assert base_files.keys() == head_files.keys(), (
    "Base and head directories must have the same subdirectories."
)

for dirname in base_files.keys():
    out = args.out_dir / f"1_{args.commit_hash}" / dirname
    out.mkdir(parents=True, exist_ok=True)
    changed = head_files[dirname] - base_files[dirname]
    if args.base_compile_commands.read_text().strip() == "{}":
        for f in changed:
            # Skip files that were directly compiled because base build failed
            # and we don't have anything to compare against.
            if json.loads(
                (args.head_dir / dirname / f).read_text()
            ).get("was_directly_compiled", False):
                continue
            shutil.copyfile(
                args.head_dir / dirname / f,
                out / f,
            )
    else:
        for f in changed:
            shutil.copyfile(
                args.head_dir / dirname / f,
                out / f,
            )
