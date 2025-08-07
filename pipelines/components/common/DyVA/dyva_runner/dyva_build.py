import shutil
import os
import yaml
import subprocess

from pathlib import Path
CUR_DIR = Path(__file__).absolute().parent.parent

def set_docker_env(target_dir: Path, language: str):
    if language == "c":
        docker_env = CUR_DIR / "modifications" / "docker_envs" / "docker_c.env"
    elif language == "java":
        docker_env = CUR_DIR / "modifications" / "docker_envs" / "docker_java.env"
    else:
        return

    shutil.copy(docker_env, target_dir / ".env.docker")

def start_remote_debugger(target_dir: Path, harness_path: Path, harness_name: str):
    shutil.copy(target_dir / harness_path, target_dir / harness_path.parent / "real_harness")
    shutil.copy(target_dir / "run_gdbserver.sh", target_dir / harness_path)
    os.chmod(target_dir / harness_path, 777)
    subprocess.Popen(["./run.sh", "run_pov", "./run.sh", harness_name], cwd=target_dir)

def build_and_run(target_dir: Path, target_metadata: Path, harness_info: Path, crashing_input: Path) -> str:
    """
    Builds the C cp_target with debug symbols and returns the docker tag of the image.
    """
    with open(target_metadata, "r") as f:
        target_metadata = yaml.safe_load(f)
    set_docker_env(target_dir, language=target_metadata["language"])
    docker_img_address = target_metadata.get("docker_image", None)
    assert(docker_img_address is not None)

    # These are also in the .env.project
    if ":" in docker_img_address:
        docker_tag = docker_img_address.split(":")[0] + "-dyva" + ":" + docker_img_address.split(":")[1]
    else:
        docker_tag = docker_img_address + "-dyva"
    
    docker_image_str = f"DOCKER_IMAGE_NAME={docker_tag}"
    env_project = target_dir / '.env.project'
    new_env_project = env_project.read_text().split("\n")
    for idx, line in enumerate(new_env_project):
        if "DOCKER_IMAGE_NAME" in line:
            new_env_project[idx] = docker_image_str
            break
    else:
        new_env_project.append(docker_image_str)
    new_env_project.append("CP_DOCKER_EXTRA_ARGS=--privileged")

    env_project.write_text("\n".join(new_env_project))

    dockerfile = CUR_DIR / "modifications" / "docker_envs" / f"Dockerfile_{target_metadata['language']}.extension"

    subprocess.run(["docker", "build", target_dir, 
                                       f"--build-arg=BASE_IMAGE={docker_img_address}", 
                                       "-t", docker_tag, 
                                       "-f", dockerfile], cwd=target_dir, check=True)
    subprocess.run(["./run.sh", "build"], cwd=target_dir, check=True)
    if target_metadata["language"] == "java": # Need to run once to get the classpath from jazzer
        subprocess.run(["./run.sh", "run_pov", "./run.sh", list(target_metadata["harnesses"].values())[0]["name"]], cwd=target_dir, check=True)
    with open(harness_info, "r") as f:
        harness_data = yaml.safe_load(f)
    start_remote_debugger(target_dir, Path(harness_data["cp_harness_binary_path"]), harness_data["cp_harness_name"])
    return docker_tag
