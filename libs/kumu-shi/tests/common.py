import subprocess
import os
import uuid
import docker
import git

from docker.models.containers import Container
from pathlib import Path
from typing import Tuple, Optional, List

from kumushi.data.program import Program
from kumushi.util import WorkDirContext


def build_and_run_docker_container(workspace_path, environment) -> Container:
    """Build and run a Docker container using Python Docker API"""
    client = docker.from_env()
    image_name = "coverage-guy-kumushi"
    container_name = f"coverage-guy-{str(uuid.uuid4())[:8]}"
    
    # Setup build context and paths
    dockerfile_path = os.path.join(workspace_path, "Dockerfile")
    
    print(f"Building Docker image: {image_name}")
    
    # Build the image
    image, build_logs = client.images.build(
        path=workspace_path,
        dockerfile=dockerfile_path,
        tag=image_name,
        pull=False,
    )
    
    # Setup volume bindings
    volumes = {
        os.path.abspath(workspace_path): {
            'bind': '/shellphish/coverageguy',
            'mode': 'cached'
        },
        os.path.abspath(os.path.join(workspace_path, '../../libs/coveragelib')): {
            'bind': '/shellphish/coveragelib',
            'mode': 'cached'
        },
        '/aixcc-backups': {
            'bind': '/aixcc-backups',
            'mode': 'cached'
        },
        '/shared': {
            'bind': '/shared',
            'mode': 'cached'
        },
        '/var/run/docker.sock': {
            'bind': '/var/run/docker.sock',
            'mode': 'rw'
        }
    }
    
    print(f"Running container: {container_name}")
    
    # Run the container
    container = client.containers.run(
        image=image_name,
        environment=environment,
        command="tail -f /dev/null",  # Keep container running
        detach=True,
        privileged=True,
        volumes=volumes,
        name=container_name,
        tty=True
    )
    
    return container

def execute_command(container: Container, 
                   commands: List[str], 
                   show_output: bool = True) -> tuple:
    """Execute commands in container and return exit code, output"""
    # Join commands with && to ensure they run in sequence
    command_string = " && ".join(commands)
    print(f"Executing: {command_string}")
    
    # Execute command
    exec_result = container.exec_run(
        f"/bin/bash -c '{command_string}'",
        tty=True,
        stream=True
    )
    
    output = []
    for line in exec_result.output:
        decoded_line = line.decode().strip()
        if show_output:
            print(decoded_line)
        output.append(decoded_line)
    
    return exec_result.exit_code, output

def build_aurora_nginx_image():
    print("Building aurora_nginx_image...")
    client = docker.from_env()
    client.images.build(dockerfile="Dockerfiles/Dockerfile.aurora-ngnix", tag="aurora_nginx_image:latest", path=str(Path(__file__).parent.absolute()))
    print("Image built successfully!")
    
def ensure_image_exists(image_name):
    client = docker.from_env()
    try:
        client.images.get(image_name)
        print(f"Image '{image_name}' exists.")
    except docker.errors.ImageNotFound:
        print(f"Image '{image_name}' not found. Building...")
        build_aurora_nginx_image()
    except docker.errors.APIError as e:
        print(f"Error accessing Docker API: {e}")
        raise

def validate_in_aurora_container(cmds) -> str:
    volumes = {
        str(Path(__file__).parent.parent.absolute()): {"bind": str(Path("/kumu-shi/")), "mode": "rw"},
        "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
        "/aixcc-backups": {"bind": "/aixcc-backups", "mode": "rw"},
        "/shared": {"bind": "/shared", "mode": "rw"},
    }
    cmds = " && ".join(cmds)
    print(f"Running command: {cmds}")
    client = docker.from_env()
    try:
        container = client.containers.run(
            "aurora_nginx_image",
            detach=False,
            command=f"/bin/bash -c '{cmds}'",
            volumes=volumes,
            tty=True,
            auto_remove=True,
        )
    except docker.errors.ContainerError as e:
        print(f"Error: {e}")
        print(f"Command: {e.command}")
        print(f"Exit status: {e.exit_status}")
        print("Container logs:")
        print(e.container.logs().decode("utf-8"))
        raise
    

def setup_coverage_guy_container(backup_name: str, language: str) -> Container:

    # export TARGET_METADATA_PATH=$TARGET_METADATA_PATH  # {{ target_metadatum_path | shquote }}
    # export LANGUAGE=$LANGUAGE  # {{ target_metadatum.language }}
    # export TARGET_DIR=$TARGET_DIR  # {{target | shquote}}
    # export TARGET_ID=$TARGET_ID  # {{target_id | shquote}}
    backups_dir = f"/aixcc-backups/{backup_name}"
    environment = {
        "TARGET_METADATA_PATH": f"{backups_dir}/coverage_build.target_metadatum/1.yaml",
        "TARGET_ID": "1",
        "TARGET_DIR": f'/shared/{backup_name}/target',
        "LANGUAGE": language.lower(),
        "RESULTS_DIR": f'/shared/{backup_name}/target',

    }


    try:
        # Get the 
        artiphishell_components = Path(os.getcwd()).absolute().parent.parent
        print(f"artiphishell path: {artiphishell_components}")
        coverageguy_path = os.path.join(artiphishell_components, "coverage-guy")
        
        # Build and run the container
        container = build_and_run_docker_container(coverageguy_path, environment)
        print(f"Successfully created and started container: {container.name}")
        if not Path('/shared/.git-credentials').exists():
            raise ValueError("No git credentials found in /shared/.git-credentials")
        
        login_commands = ['docker login ghcr.io -u $(cat /shared/.git-credentials | cut -d: -f2 | cut -d@ -f1) --password-stdin < <(cod)']
        setup_commands = [f'mkdir -p /shared/{backup_name}/target', f'tar -xvf {backups_dir}/coverage_build.target_built_with_coverage/1.tar.gz -C /shared/{backup_name}/target',
                    f'ls -la {backups_dir}/coverage_build.target_built_with_coverage/']
        build_commands = ['cd /shellphish/coverageguy/resources', 'ls -la', './run_build.sh']
        commands = login_commands + setup_commands + build_commands
        
        exit_code, output = execute_command(container, commands)
        if exit_code != 0:
            print(f"Command failed with exit code {exit_code}")

        # Return the container name for further use
        return container
        
    except subprocess.CalledProcessError as e:
        print(f"Error running Docker commands: {e}")
        print(f"Command output: {e.output}")
        raise
    except Exception as e:
        print(f"An error occurred: {e}")
        raise


#
# Mocking/Testing Classes
#

class SimpleProgram(Program):
    def __init__(self, run_script_path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._runner_path = Path(run_script_path).resolve().absolute()

    def _compile_core(self):
        with WorkDirContext(self._runner_path.parent):
            compile_cmd = f"./run.sh build "
            failed = False
            try:
                proc = subprocess.run(compile_cmd.split(), capture_output=True, text=True)
            except Exception as e:
                print(f"Compilation failed: {e}")
                failed = True
            if failed:
                repo = git.Repo(self.source_root)
                repo.git.reset("--hard")
                return False, f"Compilation failed"
            else:
                return proc.returncode == 0, proc.stdout
