import os
import sys
import tempfile
import time
import subprocess
from pathlib import Path
from typing import Tuple, Optional
from git import Repo
import docker
from docker.models.containers import Container
import functools
import random
import logging
import string

_l = logging.getLogger(__name__)

TESTDIR = Path(os.getcwd()) / "tests"
TARGET = TESTDIR / "targets"
JAZZER_SANITIZER = TESTDIR / "resources" / "jazzer_sanitizer.json"
QUERY_PATH = TESTDIR / "resources" / "codeql_queries"
QUERY_TEMPLATES_PATH = TESTDIR / "resources" / "codeql_queries_templates"

TMP_DIR = Path("/tmp/quickseed")
REPO_ROOT = Path(__file__).parent.absolute()
CONTAINER_QUICKSEED = Path("/quickseed")
CONTAINER_TESTS_DIR = CONTAINER_QUICKSEED / "tests"

def setup_aicc_target_full(
    backup_data_dir: Path,
    target_url: str,
    target_repo_name: Optional[str] = None,
) -> Tuple[Container, Path, Path]:
    # verify that we have an unpacked functions json output dir
    unpackable_dirs = ["func_json_dir"]
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
    target_dir = backup_data_dir.parent / "target"
    if not target_dir.exists():
        target_dir.mkdir()
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

    # Prepare the repo
    # Run `make cpsrc-prepare` and `make docker-pull` outside the container first
    # /tests/aicc_testing/mock_cp/target/targets-semis-aixcc-sc-mock-cp
    os.system(f"ls -la {target_repo_dir}")
    sys.stdout.flush()

    subprocess.run(
        ["make", "docker-pull"],
        cwd=str(target_repo_dir),
        check=True,
    )
    subprocess.run(
        ["make", "cpsrc-prepare"],
        cwd=str(target_repo_dir),
        check=True,
    )
    os.system(f"ls -la {target_repo_dir}/src")

    # now we have the things locally, lets set up the docker container
    client = docker.from_env()
    # mount the entire repo root for easy testing
    volumes = {
        str(REPO_ROOT.absolute()): {"bind": str(CONTAINER_QUICKSEED), "mode": "rw"},
        str(TMP_DIR): {"bind": str(TMP_DIR), "mode": "rw"},
        "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
    }

    container_target_testing_dir = CONTAINER_TESTS_DIR / backup_data_dir.parent.name
    container_target_resources_dir = container_target_testing_dir / backup_data_dir.name
    container_target_tmp_dir = TMP_DIR / target_tmp_dir.name
    container_target_src_dir = container_target_testing_dir / "target" / target_repo_name

    env = {}
    if os.environ.get("OPENAI_API_KEY"):
        env["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")
    if os.environ.get("LITELLM_KEY"):
        env["LITELLM_KEY"] = os.environ.get("LITELLM_KEY")
    else:
        env["LITELLM_KEY"] = "sk-artiphishell-da-best!!!"
    if os.environ.get("GOOGLE_API_KEY"):
        env["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY")
    if os.environ.get("ANTHROPIC_API_KEY"):
        env["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY")
    if os.environ.get("AIXCC_LITELLM_HOSTNAME"):
        env["AIXCC_LITELLM_HOSTNAME"] = os.environ.get("AIXCC_LITELLM_HOSTNAME")
    if os.environ.get("RETRIEVAL_API"):
        env["RETRIEVAL_API"] = os.environ.get("RETRIEVAL_API")
    if os.environ.get("EMBEDDING_API"):
        env["EMBEDDING_API"] = os.environ.get("EMBEDDING_API")
    env["USE_LLM_API"] = os.environ.get("USE_LLM_API", 1)


    container = client.containers.run(
        "aixcc-quickseed",
        environment={
            "SRC": str(container_target_tmp_dir),
            **env,
        },
        detach=True,
        volumes=volumes,
        tty=True,
        auto_remove=True,
    )
    # Copy the target into the container at the correct location

    time.sleep(10)

    # Execute commands inside the Docker container
    setup_command = (
        "set -ex; " +
        f"ls -la {str(container_target_src_dir)}; " +
        f"rsync -raz {str(container_target_src_dir)}/ {str(container_target_tmp_dir)}/"
    )
    exec_log = container.exec_run(f'sh -c "{setup_command}"', stream=True)
    for output in exec_log.output:
        print(output.decode(), end="")
    sys.stdout.flush()

    return container, container_target_resources_dir, container_target_tmp_dir

def not_run_on_ci(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if os.environ.get("ON_CI", False):
            return
        return func(*args, **kwargs)

    return wrapper

def run_build_command(target_root: Path, target_source: Path, sanitizer: str, instrumentation: str, project_id: str):
    """
    Run the build command for the target project
    :param target_root: Path
    :param target_source: Path
    :param sanitizer: str
    :param instrumentation: str
    """
    command = f"sudo $(which oss-fuzz-build)  {target_root} --project-id {project_id} --sanitizer {sanitizer}" + \
                f" --instrumentation {instrumentation} --project-source {target_source}"+ \
               f" --architecture x86_64"
    run_command(command)

def run_build_image_command(target_root: Path, instrumentation: str):
    command = f"sudo $(which oss-fuzz-build-image) {target_root} --instrumentation {instrumentation} --build-runner-image"
    run_command(command)

def run_command(cmd, timeout=None, on_raise=None):
    try:
        # randomize stdout and stderr filenames because this is run in parallel
        suffix = random_string(length=10)
        stdout_filename = f"/tmp/cmd_stdout_{suffix}"
        stderr_filename = f"/tmp/cmd_stderr_{suffix}"

        with open(stdout_filename, "wb") as cmd_stdout, open(stderr_filename, "wb") as cmd_stderr:
            _l.debug(f"Running command: {cmd}")
            pid = subprocess.Popen(
                cmd, shell=True, text=False, stdout=cmd_stdout, stderr=cmd_stderr
            )
            pid.communicate(timeout=timeout)
            exit_code = pid.returncode

    except subprocess.TimeoutExpired:
        _l.error(" >>> ⏰ Timeout expired for command %s <<<", cmd)
        pid.kill()
        exit_code = -1

    except subprocess.CalledProcessError:
        _l.exception("Failed to run command %s", cmd)
        exit_code = -1

    finally:
        with open(
            stdout_filename, "r", encoding="utf-8", errors="replace"
        ) as cmd_stdout, open(
            stderr_filename, "r", encoding="utf-8", errors="replace"
        ) as cmd_stderr:
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()

        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)

        if exit_code == -1:
            _l.error(f" 🤡 Fatal error during {cmd}\n{exit_code=}\n{cmd_stdout_text=}\n{cmd_stderr_text=}")
        elif exit_code != 0:
            _l.error(f" 🤡 Non-Fatal error during {cmd}\n{exit_code=}\n{cmd_stdout_text=}\n{cmd_stderr_text=}")

        # if on_raise and exit_code == -1:
        #     raise on_raise
        if exit_code != 0:
            _l.error(f"Command failed with exit code {exit_code}")
            _l.error(f"Command stdout: {cmd_stdout_text}")
            _l.error(f"Command stderr: {cmd_stderr_text}")
            raise subprocess.CalledProcessError(exit_code, cmd, output=cmd_stdout_text, stderr=cmd_stderr_text)

        return exit_code, cmd_stdout_text, cmd_stderr_text
    
def random_string(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def run_codeql_command(database_path: Path, cp_name: str, project_id: str):
    command = f"CODEQL_SERVER_URL='http://localhost:4000' codeql-upload-db  --cp_name {cp_name} " +\
         f" --project_id {project_id} --language java --db_file {database_path}"
    run_command(command)

def check_image_exists(image_name):
    client = docker.from_env()
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False