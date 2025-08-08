# given a backup, ask which poi_report to use
# copy all the directories in the backup to the out dir and keep the directory structure and keep the poi_report
# in pytest, specify the backup dir and the name of the project and the mode [full, delta]
# in pytest use patcher = AICCPatcher.from_files and patcher.generate_verified_patches to start testing

import argparse
import subprocess
import shutil
import tempfile
import os
from pathlib import Path

FILES_NEEDED = ['commit_functions_index', 'crashing_input_path', 'full_functions_index', 'full_functions_jsons_dir', 'commit_functions_jsons_dir',
                'kumushi_output', 'poi_report', 'povguy_pov_report_path', 'project_metadata_path']


def extract_tar_to_dir(tar_path: Path, output_dir: Path) -> Path:
    subprocess.run(["tar", "xf", str(tar_path), "-C", str(output_dir)], check=True)
    return Path(output_dir)




def main():
    parser = argparse.ArgumentParser(description="Backup to patchery ci_tests")
    parser.add_argument("--backup_path", type=Path, help="Path to the backup tar file")
    parser.add_argument('--heavy_mode', action='store_true', help="Run in heavy mode")
    parser.add_argument('--output_dir', type=Path, help="Output directory for extracted files")
    args = parser.parse_args()
    backup_path = args.backup_path
    output_dir = args.output_dir
    if args.heavy_mode:
        task_name = 'patchery_heavy_mode.'
    else:
        task_name = 'patchery.'
    if not backup_path.exists():
        print(f"Error: Directory '{backup_path}' does not exist")
        return
    filtered_output = tempfile.mkdtemp()
    filtered_output = Path(filtered_output)

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Extracting {backup_path} to {tmpdir}")
        backup_extract = extract_tar_to_dir(backup_path, Path(tmpdir))
        backup_dir = list(Path(backup_extract).iterdir())[0]
        backup_name = backup_dir.name
        for backup_task_dir in Path(backup_dir).iterdir():
            if backup_task_dir.is_dir() and backup_task_dir.name.startswith(task_name):
                print(f"Found task directory: {backup_task_dir}")
                if not backup_task_dir.name.split('.')[-1] in FILES_NEEDED:
                    continue
                if os.path.islink(backup_task_dir):
                    shutil.move(os.path.realpath(backup_task_dir), filtered_output / backup_task_dir.name)
                else:
                    shutil.move(backup_task_dir, filtered_output)
                print(f"Moved {backup_task_dir} to {filtered_output}")
            else:
                print(f"Skipping non-matching directory: {backup_task_dir}")
        shutil.rmtree(output_dir / backup_name, ignore_errors=True)
        print(f"Moving {task_name} filtered {backup_dir} to {output_dir / backup_name}")
        shutil.move(str(filtered_output), str(output_dir / backup_name))




if __name__ == "__main__":
    main()