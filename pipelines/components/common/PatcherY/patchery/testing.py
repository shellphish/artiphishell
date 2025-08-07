import hashlib
from pathlib import Path
import subprocess
import tempfile
import shutil

import yaml


def extract_tar_to_dir(tar_path: Path, output_dir: Path):
    subprocess.run(["tar", "xf", str(tar_path), "-C", str(output_dir)], check=True)
    output_files = list(output_dir.iterdir())
    if len(output_files) == 1 and output_files[0].is_dir():
        print("! Extracted tar file contains a single directory, moving contents to output directory...")
        # if there is only one directory in the output, move the contents of that directory to the output directory
        new_output_files = list(output_files[0].iterdir())
        for new_output_file in new_output_files:
            shutil.move(new_output_file, output_dir)
        shutil.rmtree(output_files[0])


def hash_file(tar_path: Path) -> str:
    with open(tar_path, "rb") as fp:
        data = fp.read()

    hasher = hashlib.md5()
    hasher.update(data)
    return hasher.hexdigest()


def extract_patchery_files_from_backup(backup_path: Path, output_dir: Path, overwrite: bool = False):
    """
    A backup is a tar file that contains the following files that PatcherY needs:
    - poi_report
    - pov_report
    - crashing_seeds
    - crashing_commit
    - commit_indices.json
    - function_indices.json

    """
    # sanity check things
    assert backup_path.exists(), f"Backup file {backup_path} does not exist"
    assert not backup_path.is_dir(), f"Backup file {backup_path} is a directory"

    if not output_dir.exists():
        # create the output directory
        output_dir.mkdir(parents=True)

    # extract the backup to a temporary directory
    print(f"+ Extracting backup to {output_dir}...")
    backup_data_dir_prefix = f"backup_{hash_file(backup_path)}_"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        extract_tar_to_dir(backup_path, tmpdir)

        # find all VDS records, which we will use to extract multiple files
        vds_records = list((tmpdir / "patchery.vds_record").glob("*.yaml"))
        if not vds_records:
            raise Exception(f"No VDS records found in {tmpdir / 'patchery.vds_record'}")

        for i, vds_record_yaml in enumerate(vds_records):
            backup_data_dir = output_dir / f"{backup_data_dir_prefix}{i}"
            if backup_data_dir.exists():
                if overwrite:
                    print(f"- Removing existing backup data directory {backup_data_dir}")
                    shutil.rmtree(backup_data_dir)
                else:
                    print(f"!!!! Backup data directory {backup_data_dir} already exists, skipping...")
                    continue
            backup_data_dir.mkdir()

            vds_data = yaml.safe_load(vds_record_yaml.read_text())
            vds_id = vds_record_yaml.stem
            crashing_commit_id = vds_data.get("crashing_commit_id", None)
            if crashing_commit_id is None:
                print(f"- No crashing commit id found in {vds_record_yaml}, skipping...")
                continue

            crashing_commit_file = tmpdir / f"patchery.crashing_commit/{crashing_commit_id}.yaml"
            shutil.copy(crashing_commit_file, backup_data_dir / f"crashing_commit.yaml")

            crashing_commit_data = yaml.safe_load(crashing_commit_file.read_text())
            crash_id = crashing_commit_data.get("crash_id", None)
            if crash_id is None:
                print(f"- No crash id found in {crashing_commit_file}, skipping...")
                continue

            # get the poi report
            poi_report_file = tmpdir / f"patchery.poi_report/{crash_id}.yaml"
            if not poi_report_file.exists():
                print(f"- No poi report found in {poi_report_file}, skipping...")
                continue

            # get crash
            out_crash_dir = backup_data_dir / "crashing_seeds"
            out_crash_dir.mkdir(parents=True)
            # it can be in two different places, try both
            try:
                shutil.copy(tmpdir / f"patchery.crashing_input_path/{crash_id}", out_crash_dir)
            except Exception:
                shutil.copy(tmpdir / f"patchery.crashing_input_path.__footprint.1/{crash_id}", out_crash_dir)

            # get poi report
            poi_report = tmpdir / f"patchery.poi_report/{crash_id}.yaml"
            shutil.copy(poi_report, backup_data_dir / "poi.yaml")

            # get pov report
            try:
                shutil.copy(
                    tmpdir / f"patchery.povguy_pov_report_path/{crash_id}.yaml", backup_data_dir / "report.yaml"
                )
            except Exception:
                shutil.copy(
                    tmpdir / f"patchery.povguy_pov_report_path.__footprint.0/{crash_id}.yaml",
                    backup_data_dir / "report.yaml",
                )

            # get commit indices
            shutil.copy(tmpdir / "patchery.target_commit_index/1", backup_data_dir / "commit_indices.json")
            # get function indices
            shutil.copy(tmpdir / "patchery.function_index/1", backup_data_dir / "function_indices.json")
            # get functions by commits
            shutil.copy(
                tmpdir / "patchery.target_functions_by_commits_jsons_dir/1.tar.gz",
                backup_data_dir / "functions_by_commits.tar.gz",
            )
            # get function out dir
            shutil.copy(
                tmpdir / "patchery.target_functions_jsons_dir/1.tar.gz", backup_data_dir / "function_out_dir.tar.gz"
            )

            # get the invariant report (if it exist)
            invariant_report = tmpdir / f"patchery_invariants.invariance_report/{vds_id}.yaml"
            if invariant_report.exists():
                print("+ Found invariant report, copying...")
                shutil.copy(invariant_report, backup_data_dir / "invariant_report.yaml")

            # get the debug report (if it exist)
            debug_report = tmpdir / f"patchery_debuginfo.local_variable_report/{vds_id}.yaml"
            if debug_report.exists():
                print("+ Found debug report, copying...")
                shutil.copy(debug_report, backup_data_dir / "debug_report.yaml")
