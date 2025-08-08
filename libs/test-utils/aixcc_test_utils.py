from __future__ import annotations

import logging
import subprocess
import os
import time
import shutil
import json
import requests
import tarfile

from contextlib import contextmanager
from pathlib import Path
from typing import List, Generator

import git

from rich import console, progress
from rich.logging import RichHandler
from rich.progress import Progress, BarColumn, DownloadColumn, TextColumn, TransferSpeedColumn, TimeRemainingColumn


VALID_TARGETS = {
    "mock-cp": {
        "repo": "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp",
            },
    "jenkins-cp": {
        "repo": "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp",
        },
    "full-nginx": {
        "repo": "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp",
        },
    "linux-cp": {
        "repo": "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-001-linux-cp",
        },
    "mock-cp-java-easy": {
        "repo": "https://github.com/shellphish-support-syndicate/shellphish-mock-java-easy",
        },
    "mock-cp-java": {
        "repo": "https://github.com/shellphish-support-syndicate/shellphish-mock-java",
        }
}

OSS_FUZZ_TARGETS="https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets"

CAPI_DIR = Path("/tmp/capi")
TARGET_DIR = Path("/tmp/targets")
TARGET_REPO = Path("/tmp/targets/artiphishell-ossfuzz-targets")
PROJECT_SRC = TARGET_REPO / "project_src"
COMPRESSED_TARGET_DIR = TARGET_DIR / "compressed_target"
COMPRESSED_PROJECT_DIR = TARGET_DIR / "compressed_project"
ARTIPHISHELL_ROOT = Path(__file__).parent.parent.parent.absolute()
TEST_DATA_DIR = ARTIPHISHELL_ROOT.parent / "artiphishell-tests-data"

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=console.Console(width=200))]
)

log = logging.getLogger("rich")

def clone_target(target_name: str, cache=True):
    """
    Clone the Challenge Problem.
    """
    valid_target = VALID_TARGETS[target_name]["repo"]
    TARGET_DIR.mkdir(exist_ok=True, parents=True)

    if not cache or not TARGET_REPO.exists():
        log.info("Cloning targets repo %s", OSS_FUZZ_TARGETS)
        git.Repo.clone_from(url=OSS_FUZZ_TARGETS,
                            to_path=TARGET_REPO,
                            progress=GitRemoteProgress(),
                            recursive=True)

        subprocess.run(
            ["yq", "e", f".shellphish_project_name = \"{target_name}\"", "-i", f"{TARGET_REPO}/projects/{target_name}/project.yaml"],
            check=True,
            capture_output=True
        )

        if not cache or not PROJECT_SRC.exists():
            PROJECT_SRC.mkdir(exist_ok=True, parents=True)

            # Drop the source into the targets directory
            log.info("Cloning target source %s", target_name)
            git.Repo.clone_from(url=valid_target,
                                to_path=PROJECT_SRC,
                                progress=GitRemoteProgress(),
                                recursive=True)

def prep_target(target_name: str, cache=True):
    """
    Clone the target, prepare the source, and build the docker image.
    target_name: The name of the target to prepare (Must be in VALID_TARGETS).
    """
    clone_target(target_name, cache)

    log.info("Preparing Challenge Problem: %s", target_name)

    COMPRESSED_TARGET_DIR.mkdir(exist_ok=True, parents=True)
    compressed_name = COMPRESSED_TARGET_DIR / (target_name + ".tar.gz")
    log.info("Compressing Challenge Problem to %s", str(compressed_name))
    subprocess.run(["tar", "-czf", str(compressed_name), "."], cwd=TARGET_REPO, check=True)

    COMPRESSED_PROJECT_DIR.mkdir(exist_ok=True, parents=True)
    compressed_name = COMPRESSED_PROJECT_DIR / (target_name + ".tar.gz")
    log.info("Compressing Challenge Problem to %s", str(compressed_name))
    subprocess.run(["tar", "-czf", str(compressed_name), "."], cwd=TARGET_REPO, check=True)

def unlock_pipeline():
    """
    Unlock the pipeline.
    """
    try:
        subprocess.run(["pdl", "--unlock"], check=True)
    except subprocess.CalledProcessError:
        try:
            os.unlink("pipeline.lock")
        except FileNotFoundError:
            pass

def lock_pipeline():
    """
    Lock the pipeline.
    """
    unlock_pipeline()
    subprocess.run(["pdl"], check=True)

def pipeline_inject(target: str, pd_id: str, data: bytes = None, file: Path = None):
    """
    Inject data into a pipeline target with the given id.

    target: The target to inject the data into (e.g. find_first_crash_commit.target_metadata).
    pd_id: The id of the data to inject (e.g. 222).
    data: The raw bytes to inject (required if file is None).
    file: The file to inject (required if data is None).
    """

    if file:
        data = file.read_bytes()

    log.debug("Injecting data into %s with id %s", target, pd_id)
    subprocess.run(["pd", "inject", target, pd_id], input=data, check=True)

def pipeline_list_ids(target: str) -> List[str]:
    """
    List the pipeline ids for the given target.
    """

    pipeline_ids = subprocess.run(["pd", "ls", target], check=True, capture_output=True, text=True).stdout.strip().split("\n")
    log.debug("Found %s ids", len(pipeline_ids))
    log.debug("IDs: %s", pipeline_ids)
    return pipeline_ids


def pipeline_get_data(target: str, pd_id: str) -> bytes:
    """
    Get the data from a pipeline target with the given pd_id.
    """
    return subprocess.run(["pd", "cat", target, pd_id], check=True, capture_output=True).stdout

def pipeline_run(before_args: List[str] = [], after_args: List[str] = [], timeout=None):
    """
    Run the pipeline with the given arguments before and after the run command.

    before_args: Arguments to pass inbetween `pd` and `run`.
    after_args: Arguments to pass after `run`.
    """

    log.info("Running pipeline: pd %s run %s", " ".join(before_args), " ".join(after_args))
    subprocess.run(["pd", *before_args, "run", *after_args], timeout=timeout)

def pipeline_status(output_format: str = "text") -> dict | str:
    """
    Get the status of the pipeline `pd status`

    output_format: pydatatask can output the status as text or json. Default is text.
    """

    try:
        status_cmd = ["pd", "status"]
        if output_format == "json":
            status_cmd.append("--as-json")

        result = subprocess.run(status_cmd, check=True, capture_output=True).stdout
        status = result.decode('utf-8')

        if 'ERROR - Terminated with error' in status:
            log.error(f"Pipeline status terminated with error {status}")
            return None

        if output_format == "json":
            status = json.loads(status)
        # log.debug(f"pd status:\n {status}")
        return status
    except subprocess.CalledProcessError as error:
        log.error(f"Error getting pipeline status {error.stdout}")
        return None
    except json.JSONDecodeError:
        log.error(f"Error decoding pipeline status to json {status}")
        return None

def aixcc_docker_login():
    """
    Login to the AIxCC GitHub Container Registry.
    """
    if not is_local_test():
        log.info("Logging into CI GitHub Container Registry")
        subprocess.run(["docker", "login", "ghcr.io", "-u", os.environ.get("GHCR_USERNAME"), "-p", os.environ.get("GHCR_PASSWORD")], check=True)
    else:
        log.info("Logging into AIxCC GitHub Container Registry")
        subprocess.run(["docker", "login", "ghcr.io", "-u", "player-c3f09220", "-p", "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"], check=True)

def is_local_test():
    return os.environ.get("CI") is None

def build_docker(context: Path, image_name: str, build_args: list = [], pull_dependencies_base: bool = False, pull_component_base: bool = False):
    """
    Build a docker image from a given context and tag it with the given image name.

    pull_dependencies_base: Pull the dependencies base image before building.
    pull_component_base: Pull the component base image before building.
    """
    if pull_dependencies_base:
        log.info("Pulling dependencies base image")
        subprocess.run(["docker", "pull", "ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base:latest"], check=True)
    if pull_component_base:
        log.info("Pulling component base image")
        subprocess.run(["docker", "pull", "ghcr.io/shellphish-support-syndicate/aixcc-component-base:latest"], check=True)

    log.info("Building docker image %s", image_name)
    build_cmd = ["docker", "build", context, "-t", image_name]
    for arg in build_args:
        build_cmd.append("--build-arg")
        build_cmd.append(arg)
    subprocess.run(build_cmd, check=True)

def pull_latest_ci_backup(target: str) -> Path:
    """_summary_
    Use the Github API to pull the latest CI backup for the given target from the artiphishell-ci-results repo.

    Args:
        target (str): Must be a valid target in VALID_TARGETS.
    """
    assert target in VALID_TARGETS
    token = os.environ.get("GITHUB_TOKEN")
    if token is None:
        token_file = Path.home() / ".github-token"
        if not token_file.exists():
            token = input("Please enter your github token or set GITHUB_TOKEN environment variable: ")
            token_file.write_text(token)
        else:
            token = token_file.read_text()

    headers = {
        "Accept": "application/vnd.github.raw+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    pipeline_json_url = "https://api.github.com/repos/shellphish-support-syndicate/artiphishell-ci-results/contents/pipeline-runs.json"
    pipeline_json = requests.get(pipeline_json_url, headers=headers).json()
    target = target if target == "mock-cp" else target.replace("-cp", "")
    backup_url = sorted(pipeline_json[target], key=lambda x: x["end_time"], reverse=True)[0]["pipeline"]["backup_url"]
    backup_location = download_file(backup_url, target)
    log.info("latest CI backup for %s at %s", target, backup_location)
    return backup_location

def restore_from_backup(target: str, component_name: str, backup_dir: Path):
    subprocess.run(["pd", "resotre", str(backup_dir), component_name + "*"])

def pipeline_inject_all_files_from_dir(backup_dir: Path, component_target: str):
    for file in (backup_dir / component_target).iterdir():
        pipeline_inject(component_target, pd_id=file.stem, file=file)

def download_file(url: str, target: str) -> Path:
    latest_file = Path("/tmp", url.split('/')[-1])
    tar_filename = Path("/tmp", target + "-backup.tar.gz")
    extract_dir = Path("/tmp", target)
    if latest_file.exists():
        extract_dir = list(extract_dir.iterdir())[0]
        return extract_dir
    latest_file.touch()
    shutil.rmtree(extract_dir, ignore_errors=True)

    # Get the file size from the headers
    response = requests.head(url)
    total_size = int(response.headers.get('content-length', 0))

    with Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.1f}%",
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
    ) as progress:

        # Create the task for the progress bar
        task = progress.add_task("Downloading", filename=str(tar_filename), total=total_size)

        # Stream the download in chunks
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with tar_filename.open("wb") as f:
                for chunk in r.iter_content(chunk_size=8192):  # Download in 8KB chunks
                    f.write(chunk)
                    progress.update(task, advance=len(chunk))

    tar_file = tarfile.open(tar_filename)
    tar_file.extractall(extract_dir)
    tar_file.close()
    os.unlink(tar_filename)

    extract_dir = list(extract_dir.iterdir())[0]
    # Initialize progress bar
    return extract_dir

# pd --unlock doesn't seem to remove all the fuzzing docker containers
def kill_docker_containers(prefix: str):
    """
    Kill all docker containers with the given prefix in name.

    prefix: The prefix of the container(s) name to kill.
    """
    try:
        result = subprocess.run(['docker', 'ps', '--format', '{{.ID}} {{.Names}}'], capture_output=True, text=True, check=True)
        containers = result.stdout.strip().split('\n')
        containers_to_kill = [container.split()[0] for container in containers if container.split()[1].startswith(prefix)]
        if not containers_to_kill:
            log.debug(f"No containers found with prefix '{prefix}'.")
            return

        for container_id in containers_to_kill:
            log.debug(f"Killing container: {container_id}")
            subprocess.run(['docker', 'kill', container_id], check=True)
            subprocess.run(['docker', 'rm', container_id], check=True)
        log.debug(f"Successfully killed {len(containers_to_kill)} containers.")

    except subprocess.CalledProcessError as e:
        log.error(f"Error occurred while killing containers: {e}")

@contextmanager
def capi(target: str) -> Generator[subprocess.Popen]:
    """
    Context manager for the CAPI docker-compose environment.
    """
    url = "https://github.com/shellphish-support-syndicate/aixcc-sc-capi.git"
    # if CAPI_DIR.exists():
    #     shutil.rmtree(CAPI_DIR)

    if not CAPI_DIR.exists():
        log.info("Cloning CAPI...")
        repo = git.Repo.clone_from(url=url,
                                    to_path=CAPI_DIR,
                                    progress=GitRemoteProgress())
    else:
        repo = git.Repo(CAPI_DIR)
    repo.git.checkout("1d920a320f0178cd2287ad5d76225e678fbc2c0e")

    if not (CAPI_DIR / ".env").exists():
        shutil.copy(CAPI_DIR / "env.example", CAPI_DIR / "env")

    if not (CAPI_DIR / "cp_root").exists():
        log.info("Making CAPI...")
        subprocess.run(["make", target], cwd=CAPI_DIR, check=True)
        shutil.rmtree(CAPI_DIR / "cp_root" / target)
        clone_target(target, cache=True)
        shutil.copytree(TARGET_DIR / target, CAPI_DIR / "cp_root" / target)

        subprocess.run(["make", "cpsrc-prepare"], cwd=CAPI_DIR / "cp_root" / target, check=True)

    subprocess.run(["sudo", "chown", "-R", "1000:1000", CAPI_DIR / "cp_root"], check=True)

    capi_proc = None
    try:
        log.info("Taking down previous CAPI instance...")
        subprocess.run(["make", "down-volumes"], cwd=CAPI_DIR)
        log.info("Spinning up new CAPI instance...")
        capi_proc = subprocess.Popen(["docker", "compose", "up", "-d"], env={"WEB_CONCURRENCY": "5"}, cwd=CAPI_DIR)
        capi_ready = False
        while not capi_ready or not capi_proc.poll():
            time.sleep(1)
            log.info("Checking if CAPI is ready...")
            running_containers = subprocess.run(["docker", "ps", "-f", "status=running"], capture_output=True, text=True, check=True).stdout
            if not running_containers.count("capi-") == 5:
                continue
            try:
                subprocess.run(["docker", "exec", "-t", "capi-capi-1", "docker", "images"], check=True, capture_output=True)
                log.info("CAPI is ready!")
                break
            except subprocess.CalledProcessError:
                continue

        yield capi_proc

    finally:
        log.info("Cleaning up CAPI")
        subprocess.run(["docker", "compose", "down"], cwd=CAPI_DIR)
        if capi_proc:
            capi_proc.terminate()


# Yoinked this from https://stackoverflow.com/questions/51045540/python-progress-bar-for-git-clone
class GitRemoteProgress(git.RemoteProgress):
    OP_CODES = [
        "BEGIN",
        "CHECKING_OUT",
        "COMPRESSING",
        "COUNTING",
        "END",
        "FINDING_SOURCES",
        "RECEIVING",
        "RESOLVING",
        "WRITING",
    ]
    OP_CODE_MAP = {
        getattr(git.RemoteProgress, _op_code): _op_code for _op_code in OP_CODES
    }

    def __init__(self) -> None:
        super().__init__()
        self.progressbar = progress.Progress(
            progress.SpinnerColumn(),
            # *progress.Progress.get_default_columns(),
            progress.TextColumn("[progress.description]{task.description}"),
            progress.BarColumn(),
            progress.TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            "eta",
            progress.TimeRemainingColumn(),
            progress.TextColumn("{task.fields[message]}"),
            console=console.Console(),
            transient=False,
        )
        self.progressbar.start()
        self.active_task = None

    def __del__(self) -> None:
        # logger.info("Destroying bar...")
        self.progressbar.stop()

    @classmethod
    def get_curr_op(cls, op_code: int) -> str:
        """Get OP name from OP code."""
        # Remove BEGIN- and END-flag and get op name
        op_code_masked = op_code & cls.OP_MASK
        return cls.OP_CODE_MAP.get(op_code_masked, "?").title()

    def update(
        self,
        op_code: int,
        cur_count: str | float,
        max_count: str | float | None = None,
        message: str | None = "",
    ) -> None:
        # Start new bar on each BEGIN-flag
        if op_code & self.BEGIN:
            self.curr_op = self.get_curr_op(op_code)
            # logger.info("Next: %s", self.curr_op)
            self.active_task = self.progressbar.add_task(
                description=self.curr_op,
                total=max_count,
                message=message,
            )

        self.progressbar.update(
            task_id=self.active_task,
            completed=cur_count,
            message=message,
        )

        # End progress monitoring on each END-flag
        if op_code & self.END:
            # logger.info("Done: %s", self.curr_op)
            self.progressbar.update(
                task_id=self.active_task,
                message=f"[bright_black]{message}",
            )
