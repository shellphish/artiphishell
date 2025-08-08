import os
import time
import hashlib
import shlex

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.crs_reports import RunImageResult

def execute_command_in_builder(project: OSSFuzzProject, command: str, build_src: str, build_src_docker: str) -> RunImageResult:
    """Execute a command in the builder image after changing to the specified directory.
    
    Args:
        command: The command to execute.
        path: The directory path (inside the container) to cd into before execution.
    
    Returns:
        Result from the builder image execution.
    """
    # Generate unique filename using timestamp and random hash
    timestamp = int(time.time())
    random_bytes = os.urandom(32)
    random_hash = hashlib.sha1(random_bytes).hexdigest()
    command_file_name = f"cmd_{timestamp}_{random_hash}.sh"
    
    # Create full path to temporary command file in host's artifacts/work directory
    project_path = project.project_path
    command_file_host = project_path / "artifacts" / "work" / command_file_name

    # Write command script with cd and target command
    with open(command_file_host, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("cp -R /out/src/* /src/\n")
        f.write(f"cd {shlex.quote(str(build_src_docker))} || exit 1\n")  # Fail if directory change unsuccessful
        f.write(f"{command}\n")
    
    # Set execute permissions for the script
    command_file_host.chmod(0o755)
    
    try:
        # Execute in builder image using docker-relative path
        command_in_docker = f"/work/{command_file_name}"
        # assert str(build_src).startswith("/shared")
        
        # March 28th morning discussion ☕️
        # NOTE: the task service CANNOT mount folders in the container, so the next line won't 
        # work if you are using the task service to execute the command!
        # NOTE: similarly to before, the /work cannot be mounted during the task service execution
        # NOTE: Lukas' comment: this way to execute things is not a good fit for the task service
        #       because it is a one shot task. The results are gonna be immortalized in the pipeline
        #       forever and we don't really need that.
        if project.use_task_service == True:
            # Extra sure we are doing local custom runs.
            project.use_task_service = False
        built = project.builder_image_run(command_in_docker, volumes={build_src: build_src_docker})
    finally:
        # Cleanup temporary file whether execution succeeds or fails
        command_file_host.unlink()
    
    return built
