import os
import subprocess
from pathlib import Path
import logging
from typing import Optional, Tuple
import functools
import tempfile
import yaml
import re

import git
from git import Repo
import docker
from docker.models.containers import Container

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

PATCH_OUTPUT_PATH_REGEX = 'Verified patch saved to: "(.*)"'

logging.getLogger("patchery").setLevel(logging.DEBUG)


def not_run_on_ci(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if os.environ.get("ON_CI", False):
            return
        return func(*args, **kwargs)

    return wrapper


def setup_aicc_target(
    backup_data_dir: Path,
    target_url: str,
    target_repo_name: Optional[str] = None,
    ossfuzz_target=False,
) -> Tuple[Container, Path, Path]:
    # verify that we have an unpacked functions json output dir
    unpackable_dirs = ("function_out_dir", "functions_by_commits")
    for unpackable_dir in unpackable_dirs:
        unpackable_dir: Path = Path(backup_data_dir) / unpackable_dir
        if not unpackable_dir.exists():
            unpackable_dir.mkdir()
            tar_file = unpackable_dir.with_suffix(".tar.gz")
            if not tar_file.exists():
                raise FileNotFoundError(f"Did not find {tar_file}")

            subprocess.run(
                ["tar", "xC", str(unpackable_dir), "-f", str(unpackable_dir.with_suffix(".tar.gz"))], check=True
            )

    # make sure we have the mountable testing temp dir
    target_dir = backup_data_dir.parent / TARGET_DIR
    target_name = target_dir.name
    if not TMP_DIR.exists():
        TMP_DIR.mkdir()

    # give us a new temp dir for the testing
    temp_dir = tempfile.mkdtemp(dir=str(TMP_DIR), suffix=f"_{target_name}")
    target_tmp_dir = Path(temp_dir)

    if target_repo_name is None:
        target_repo_name = target_url.split("/")[-1].split(".git")[0]

    # git clone if we don't already have it
    target_repo_dir = target_dir / target_repo_name
    if not target_repo_dir.exists():
        # normal target, just clone down the remote
        Repo.clone_from(target_url, str(target_repo_dir))

    # reset the repo and pull to update it
    repo = Repo(str(target_repo_dir))
    repo.git.reset("--hard")
    repo.git.pull()

    # now we have the things locally, lets set up the docker container
    client = docker.from_env()
    # mount the entire repo root for easy testing
    volumes = {
        str(REPO_ROOT.absolute()): {"bind": str(CONTAINER_PATCHERY), "mode": "rw"},
        str(TMP_DIR): {"bind": str(TMP_DIR), "mode": "rw"},
        "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
    }

    container_target_testing_dir = (
        AICC_TEST_DIR / backup_data_dir.parent.name
        if not ossfuzz_target
        else OSSFUZZ_TEST_DIR / backup_data_dir.parent.name
    )
    container_target_resources_dir = container_target_testing_dir / backup_data_dir.name
    container_target_tmp_dir = TMP_DIR / target_tmp_dir.name
    container_target_src_dir = container_target_testing_dir / TARGET_DIR / target_repo_name

    container = client.containers.run(
        "aixcc-patchery-tests",
        environment={"DOCKER_IMAGE_NAME": "aixcc-patchery-tests-internal", "SRC": str(container_target_tmp_dir)},
        detach=True,
        volumes=volumes,
        tty=True,
        auto_remove=True,
    )
    # Execute commands inside the Docker container
    setup_command = (
        f"git config --global credential.helper 'store --file ~/.git-credentials' && "
        f"echo 'https://git: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@github.com' > ~/.git-credentials && "
        f"rsync -raz {str(container_target_src_dir)}/ {str(container_target_tmp_dir)}/ && "
        f"cd {str(container_target_tmp_dir)} && "
        "DOCKER_IMAGE_NAME=aixcc-patchery-tests-internal && "
        "docker login ghcr.io -u player-c3f09220 -p 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 && "
        "make cpsrc-prepare && "
        # "make docker-pull &&"
        "CP_DOCKER_IMAGE=aixcc-patchery-tests-internal "
        "make docker-build"
    )
    exec_log = container.exec_run(f'sh -c "{setup_command}"', stream=True)
    for output in exec_log.output:
        print(output.decode(), end="")

    return container, container_target_resources_dir, container_target_tmp_dir


def run_and_validate_patcher(
    container,
    resource_dir,
    tmp_dir,
    local_backup_dir: Path,
    crashing_commit=None,
    poi_file="poi.yaml",
    report_file="report.yaml",
    extra_patch_args=None,
    use_func_indices=True,
    use_poi_report=True,
):
    # recover crashing commit if nothing was provided
    if crashing_commit is None:
        crashing_commit_yaml = yaml.safe_load((local_backup_dir / "crashing_commit.yaml").read_text())
        crashing_commit = crashing_commit_yaml["crashing_commit"]
    if crashing_commit is None:
        raise ValueError("No crashing commit provided or found in the crashing_commit.yaml file!")

    # recover the sanitizer string from the local data (this is given normally in the pipeline)
    project_ymls = list(local_backup_dir.parent.rglob("project.yaml"))
    assert len(project_ymls) == 1, f"Found {len(project_ymls)} project.yaml files! There should only be one!"
    project_yml = project_ymls[0]
    project_data = yaml.safe_load(project_yml.read_text())
    report_data = yaml.safe_load((local_backup_dir / report_file).read_text())
    sanitizer_ids = report_data["consistent_sanitizers"]
    assert len(sanitizer_ids) == 1, f"Expected 1 sanitizer, got {len(sanitizer_ids)}!"
    sanitizer_id = sanitizer_ids[0]
    sanitizer_string = project_data["sanitizers"][sanitizer_id]

    # construct the full command that will be run inside the docker container
    func_idx_str = (
        (
            f"--function-json-dir {str(resource_dir / 'function_out_dir')} "
            f"--function-indices {str(resource_dir / 'function_indices.json')} "
            f"--functions-by-commit-jsons-dir {str(resource_dir / 'functions_by_commits')} "
            f"--indices-by-commit {str(resource_dir / 'commit_indices.json')} "
        )
        if use_func_indices
        else ""
    )
    poi_str = f"--report-yaml {str(resource_dir / poi_file)} " if use_poi_report else ""
    command = (
        (
            f"patchery --generate-aixcc-patch "
            f"--target-root {str(tmp_dir)} "
            f"--alerting-inputs {str(resource_dir / 'crashing_seeds')} "
            f"--patch-output-dir {str(tmp_dir / 'patches')} "
            f"--patch-meta-output-dir {str(tmp_dir / 'patches_meta')} "
            f"--raw-report {str(resource_dir / report_file)} "
            f'--sanitizer-string "{sanitizer_string}" '
        )
        + func_idx_str
        + poi_str
        + (f"--crashing-commit {crashing_commit} " if crashing_commit is not None else "")
        + (extra_patch_args if extra_patch_args is not None else "")
    )

    # breakpoint here is you want to debug inside the docker container before the entire patchery is run.
    # you can just copy the command and run it inside the container
    print(f"Running command: {command}")
    exec_log = container.exec_run(command, stream=True)
    output_text = ""
    for output in exec_log.output:
        _out = output.decode()
        output_text += _out
        print(_out, end="")

    # check if the patch was generated
    patch_paths = re.findall(PATCH_OUTPUT_PATH_REGEX, output_text)
    assert len(patch_paths) > 0, "No validated patch was generated!"

    for patch_path in patch_paths:
        patch_path = Path(patch_path.strip())
        assert patch_path.exists(), f"Patch path {patch_path} does not exist!"

        # check if the patch is not empty
        assert patch_path.stat().st_size > 0, f"Patch {patch_path} is empty!"
