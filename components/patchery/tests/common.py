import sys
import time
import subprocess
from pathlib import Path
import logging
from typing import Optional, Tuple
import functools
import tempfile
import yaml
import re
import os
import shutil

from git import Repo
# import docker
# from docker.models.containers import Container

# HARD CODE FOR TESTING
os.environ["LITELLM_KEY"] = "sk-artiphishell"
os.environ["USE_LITELLM"] = "1"
os.environ["AIXCC_LITELLM_HOSTNAME"] = "http://wiseau.seclab.cs.ucsb.edu:666/"

DEBUG = True if os.getenv("DEBUG", False) else False
POI_KEYED_REPO = ['crashing_input_path','kumushi_light_mode_output', 'kumushi_heavy_mode_output',
                  'poi_report', 'povguy_pov_report_path', 'project_metadata_path']

DATA_NEEDED = ['commit_functions_index', 'crashing_input_path', 'full_functions_index',
                'full_functions_jsons_dir', 'commit_functions_jsons_dir',
                'kumushi_light_mode_output', 'kumushi_heavy_mode_output', 'poi_report',
                'povguy_pov_report_path', 'project_metadata_path']

# generic stuff
TEST_DIR = Path(__file__).parent.absolute()
TEST_FEATURE_DIR = Path(__file__).parent.parent.absolute() / "test_features"
GENERIC_TEST_DIR = TEST_DIR / "generic_tests"
TARGETS = GENERIC_TEST_DIR / "targets"
PATCHES = GENERIC_TEST_DIR / "patches"
REPORTS = GENERIC_TEST_DIR / "reports"

# aicc stuff
REPO_ROOT = TEST_DIR.parent
CONTAINER_PATCHERY = Path("/patchery/")
CONTAINER_TESTS_DIR = CONTAINER_PATCHERY / "tests"
AICC_TEST_DIR = CONTAINER_TESTS_DIR / "aicc_testing"
OSSFUZZ_TEST_DIR = CONTAINER_TESTS_DIR / "ossfuzz_testing"
TARGET_DIR = "target"
RESOURCES_DIR = "resources"
TMP_DIR = Path("/tmp/patchery")
SOURCE_DIR = "source_repo"
ON_CI = os.environ.get("ON_CI", False)
if not TMP_DIR.exists():
    os.makedirs(TMP_DIR, exist_ok=True)

PATCH_OUTPUT_PATH_REGEX = 'Verified patch saved to: "(.*)"'

logging.getLogger("patchery").setLevel(logging.DEBUG)


def not_run_on_ci(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if os.environ.get("ON_CI", False):
            return
        return func(*args, **kwargs)

    return wrapper


def extract_tar_to_dir(tar_path: Path, output_dir: Path) -> Path:
    subprocess.run(["tar", "xf", str(tar_path), "-C", str(output_dir)], check=True)
    return Path(output_dir)



def setup_aicc_backup_target(
        target_url: str,
        target_repo_name: str,
        backup_data_dir: Path,
        poi_report_id: str
) -> Tuple[Path, Path, dict[str, Path | None]]:
    """
    Setup the target and source repo for aicc testing
    Args:
        target_url (str): The git url of the target repo
        target_repo_name (str): The name of the target repo
        backup_data_dir (Path): The path to the backup data dir
    Returns:
        Tuple[Path, Path, dict[str, Path]]: The target repo dir, source repo dir, and the data locations
    """
    if not backup_data_dir.exists():
        raise FileNotFoundError(f"Backup data dir {backup_data_dir} does not exist")

    oss_fuzz_target_dir = TEST_DIR / 'oss_fuzz_targtes'
    source_repo_dir = TEST_DIR / 'source_repos'
    os.makedirs(oss_fuzz_target_dir, exist_ok=True)
    os.makedirs(source_repo_dir, exist_ok=True)
    shutil.rmtree(oss_fuzz_target_dir, ignore_errors=True)
    Repo.clone_from(target_url, oss_fuzz_target_dir)
    print(f"Cloned {target_url} to {oss_fuzz_target_dir}")
    target_repo_dir = oss_fuzz_target_dir / 'projects' / target_repo_name
    target_project_yml = list(target_repo_dir.glob("project.yaml"))[0]
    if target_project_yml.is_file():
        with open(target_project_yml, 'r') as f:
            project_data = yaml.safe_load(f)
            source_url = project_data["main_repo"]
    shutil.rmtree(source_repo_dir / target_repo_name , ignore_errors=True)
    Repo.clone_from(source_url, source_repo_dir / target_repo_name)
    print(f"Cloned {source_url} to {source_repo_dir / target_repo_name}")

    data_locations = {}
    for data_dir in backup_data_dir.iterdir():
        if data_dir.name in POI_KEYED_REPO:
            for file in data_dir.iterdir():
                if file.name.startswith(poi_report_id):
                    data_locations[data_dir.name.split('.')[-1]] = file
                    break
        else:
            for file in data_dir.iterdir():
                full_file_name = file.name
                if full_file_name.endswith(".tar.gz") and file.exists():
                    file_name = full_file_name.split(".")[0]
                    print(f"Extracting {file} to {data_dir / file_name}")
                    os.makedirs(data_dir / file_name, exist_ok=True)
                    extract_tar_to_dir(file, data_dir / file_name)
                else:
                    file_name = full_file_name
                data_locations[data_dir.name.split('.')[-1]] = data_dir / file_name
    for data_dir in DATA_NEEDED:
        if data_dir not in data_locations:
            data_locations[data_dir] = None

    return target_repo_dir, source_repo_dir / target_repo_name, data_locations




# def setup_aicc_target(
#     backup_data_dir: Path,
#     target_url: str,
#     target_repo_name: Optional[str] = None,
#     root_dir_in_target_repo: str =  None,
# ) -> Tuple[Container, Path, Path, Path]:
#     # verify that we have an unpacked functions json output dir
#     unpackable_dirs = ("function_out_dir", "functions_by_commits")
#     for unpackable_dir in unpackable_dirs:
#         unpackable_dir: Path = Path(backup_data_dir) / unpackable_dir
#         if not unpackable_dir.exists():
#             unpackable_dir.mkdir()
#             tar_file = unpackable_dir.with_suffix(".tar.gz")
#             if not tar_file.exists():
#                 raise FileNotFoundError(f"Did not find {tar_file}")
#
#             subprocess.run(
#                 ["tar", "xC", str(unpackable_dir), "-f", str(unpackable_dir.with_suffix(".tar.gz"))], check=True
#             )
#
#     # make sure we have the mountable testing temp dir
#     target_dir = backup_data_dir.parent / TARGET_DIR
#     target_name = target_dir.name
#     if not TMP_DIR.exists():
#         TMP_DIR.mkdir()
#
#     # give us a new temp dir for the testing
#     temp_dir = tempfile.mkdtemp(dir=str(TMP_DIR), suffix=f"_{target_name}")
#     target_tmp_dir = Path(temp_dir)
#
#     if target_repo_name is None:
#         target_repo_name = target_url.split("/")[-1].split(".git")[0]
#
#     # git clone if we don't already have it
#     target_repo_dir = target_dir / target_repo_name
#     if not target_repo_dir.exists():
#         # normal target, just clone down the remote
#         Repo.clone_from(target_url, str(target_repo_dir))
#
#     if root_dir_in_target_repo:
#         target_repo_dir = target_repo_dir / root_dir_in_target_repo
#
#     # get and clone the source git repo from the local data (this is given normally in the pipeline)
#     project_ymls = list(target_repo_dir.rglob("project.yaml"))
#     assert len(project_ymls) == 1, f"Found {len(project_ymls)} project.yaml files! There should only be one!"
#     project_yml = project_ymls[0]
#     project_data = yaml.safe_load(project_yml.read_text())
#
#     # Get the source dir
#     source_url = project_data["main_repo"]
#     if not source_url:
#         raise ValueError("No main repo found in project.yaml!")
#     if not source_url.endswith(".git"):
#         source_url += ".git"
#     source_dir = backup_data_dir.parent / SOURCE_DIR
#
#     if not source_dir.exists():
#         Repo.clone_from(source_url, str(source_dir))
#
#     # Read the dir in docker that we need to map source_dir to
#     # spell
#     metadata_path_yaml = backup_data_dir / 'metadata.yaml'
#     if not metadata_path_yaml.exists():
#         raise FileNotFoundError(f"Did not find {metadata_path_yaml}, go copy it from analyze_target.metadata_path")
#     metadata_yaml = yaml.safe_load(metadata_path_yaml.read_text())
#     container_target_src_dir = metadata_yaml.get('shellphish', {}).get('source_repo_path', None)
#     assert container_target_src_dir, f"Failed to find source_repo_path in {metadata_path_yaml}"
#
#     #yamls = list(metadata_path_yaml.glob("*.yaml"))
#     #assert len(yamls) == 1, f"Found {len(yamls)} metadata yaml files! There should only be one!"
#     #metadata_yaml = yaml.safe_load(yamls[0].read_text())
#     #container_target_src_dir = metadata_yaml.get('shellphish', {}).get('source_repo_path', None)
#     #assert container_target_src_dir, f"Failed to find source_repo_path in {yamls[0]}"
#
#     # now we have the things locally, lets set up the docker container
#     client = docker.from_env()
#     # mount the entire repo root for easy testing
#     volumes = {
#         str(REPO_ROOT.absolute()): {"bind": str(CONTAINER_PATCHERY), "mode": "rw"},
#         str(TMP_DIR): {"bind": str(TMP_DIR), "mode": "rw"},
#         str(source_dir): {"bind": str(container_target_src_dir), "mode": "rw"},
#         "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
#     }
#
#     container_target_testing_dir = AICC_TEST_DIR / backup_data_dir.parent.name
#     container_target_resources_dir = container_target_testing_dir / backup_data_dir.name
#     container_target_tmp_dir = TMP_DIR / target_tmp_dir.name
#     container_target_target_dir = container_target_testing_dir / TARGET_DIR / target_repo_name
#     if root_dir_in_target_repo:
#         container_target_target_dir = container_target_target_dir / root_dir_in_target_repo
#
#     env = {}
#     if os.environ.get("OPENAI_API_KEY"):
#         env["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")
#     if os.environ.get("LITELLM_KEY"):
#         env["LITELLM_KEY"] = os.environ.get("LITELLM_KEY")
#     else:
#         env["LITELLM_KEY"] = "sk-artiphishell"
#     if os.environ.get("GOOGLE_API_KEY"):
#         env["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY")
#     if os.environ.get("ANTHROPIC_API_KEY"):
#         env["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY")
#     if os.environ.get("AIXCC_LITELLM_HOSTNAME"):
#         env["AIXCC_LITELLM_HOSTNAME"] = os.environ.get("AIXCC_LITELLM_HOSTNAME")
#     if os.environ.get("RETRIEVAL_API"):
#         env["RETRIEVAL_API"] = os.environ.get("RETRIEVAL_API")
#     if os.environ.get("EMBEDDING_API"):
#         env["EMBEDDING_API"] = os.environ.get("EMBEDDING_API")
#     env["USE_LLM_API"] = os.environ.get("USE_LLM_API", 1)
#     from docker import DockerClient
#     client = DockerClient(base_url="unix://var/run/docker.sock", timeout=300)
#
#     container = client.containers.run(
#         "aixcc-patchery",
#         environment={
#             "SRC": str(container_target_tmp_dir),
#             **env,
#         },
#         detach=True,
#         volumes=volumes,
#         tty=True,
#         auto_remove=True,
#     )
#     # Copy the target into the container at the correct location
#
#     time.sleep(10)
#
#     # Execute commands inside the Docker container
#     setup_command = (
#         "set -ex; " +
#         f"ls -la {str(container_target_target_dir)}; " +
#         f"rsync -raz {str(container_target_target_dir)}/ {str(container_target_tmp_dir)}/"
#     )
#     exec_log = container.exec_run(f'sh -c "{setup_command}"', stream=True)
#     for output in exec_log.output:
#         print(output.decode(), end="")
#     sys.stdout.flush()
#
#     return container, container_target_resources_dir, container_target_tmp_dir, container_target_src_dir
#
# def run_and_validate_patcher(
#     container,
#     resource_dir,
#     tmp_dir,
#     src_dir,
#     local_backup_dir: Path,
#     crashing_commit=None,
#     poi_file="poi.yaml",
#     report_file="report.yaml",
#     extra_patch_args=None,
#     use_func_indices=True,
#     use_poi_report=True,
# ):
#     # recover the sanitizer string from the local data (this is given normally in the pipeline)
#     report_data = yaml.safe_load((local_backup_dir / report_file).read_text())
#     sanitizer_string = report_data['consistent_sanitizers']
#     assert len(sanitizer_string) >= 1, f"No sanitizer found in the report data!"
#     sanitizer_string = sanitizer_string[-1]
#     sanitizer_to_build_with = report_data['sanitizer']
#
#     # construct the full command that will be run inside the docker container
#     func_idx_str = (
#         (
#             f"--function-json-dir {str(resource_dir / 'function_out_dir')} "
#             f"--function-indices {str(resource_dir / 'function_indices.json')} "
#             f"--functions-by-commit-jsons-dir {str(resource_dir / 'functions_by_commits')} "
#             f"--indices-by-commit {str(resource_dir / 'commit_indices.json')} "
#         )
#         if use_func_indices
#         else ""
#     )
#     poi_str = f"--report-yaml {str(resource_dir / poi_file)} " if use_poi_report else ""
#     buf_clean_str = "stdbuf -o0 -e0 timeout 900 " if ON_CI else ""
#     command = (
#         (
#             buf_clean_str + f"patchery --generate-aixcc-patch "
#             f"--target-root {str(tmp_dir)} "
#             f"--source-root {str(src_dir)} "
#             f"--alerting-inputs {str(resource_dir / 'crashing_seeds')} "
#             f"--patch-output-dir {str(tmp_dir / 'patches')} "
#             f"--patch-meta-output-dir {str(tmp_dir / 'patches_meta')} "
#             f"--raw-report {str(resource_dir / report_file)} "
#             f'--sanitizer-string "{sanitizer_string}" '
#             f'--sanitizer {sanitizer_to_build_with} '
#         )
#         + func_idx_str
#         + poi_str
#         + (f"--crashing-commit {crashing_commit} " if crashing_commit is not None else "")
#         + ('--local-run ')
#         + (extra_patch_args if extra_patch_args is not None else "")
#         + ""
#     )
#
#     # breakpoint here is you want to debug inside the docker container before the entire patchery is run.
#     # you can just copy the command and run it inside the container
#     if DEBUG:
#         print("=====================================")
#         print("# Copy and run the following command in another terminal:")
#         print(f"docker exec -it {container.id} /bin/bash -c '{command}'")
#         print("=====================================")
#         breakpoint()
#
#     exec_log = container.exec_run(command, stream=True)
#     output_text = ""
#     for output in exec_log.output:
#         _out = output.decode()
#         output_text += _out
#         print(_out, end="")
#
#     # check if the patch was generated
#     patch_paths = re.findall(PATCH_OUTPUT_PATH_REGEX, output_text)
#     assert len(patch_paths) > 0, "No validated patch was generated!"
#     print("Found patches:", patch_paths)
#
#     for patch_path in patch_paths:
#         patch_path = Path(patch_path.strip())
#         assert patch_path.exists(), f"Patch path {patch_path} does not exist!"
#
#         # check if the patch is not empty
#         assert patch_path.stat().st_size > 0, f"Patch {patch_path} is empty!"
#
