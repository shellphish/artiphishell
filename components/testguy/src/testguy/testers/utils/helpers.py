import os
import time
import hashlib
import shlex
import json
import subprocess
import logging

from tqdm import tqdm
from pathlib import Path
from typing import List
from rich import print

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
        f.write("cp -R /out/src/* /src\n")
        # f.write("sleep infinity\n")
        f.write(f"cd {shlex.quote(str(build_src_docker))} || exit 1\n")  # Fail if directory change unsuccessful
        f.write(f"{command}\n")
    
    # Set execute permissions for the script
    command_file_host.chmod(0o755)
    
    try:
        # Execute in builder image using docker-relative path
        command_in_docker = f"/work/{command_file_name}"
        assert str(build_src).startswith("/shared")
        built = project.builder_image_run(command_in_docker, volumes={build_src: build_src_docker})
    finally:
        # Cleanup temporary file whether execution succeeds or fails
        command_file_host.unlink()
    
    return built

def get_build_src_c(project_path: Path, compile_cmd_path: Path) -> List[Path]:
    """
    Get the build src path for the C/C++ projects leveraging the compile commands.

    IMPORTANT: It provides you the paths inside "project_path / artifacts / built_src"
    """
    print('\n--------------------------------------------')
    print(f"🔍 Searching for the true build src path...")
    analysis_src = project_path / 'artifacts' / 'source_root'
    compile_cmd = json.load(open(compile_cmd_path))
    logging.info(f"Found {len(compile_cmd)} compile commands.")

    # main algorithm
    potential_code_paths = []
    for cmd in tqdm(compile_cmd):
        file_path = cmd['file']
        file_path = file_path.split('/') if file_path[0] != '/' else file_path[1:].split('/')
        code_path = None
        for i in range(1, len(file_path)+1):
            path = '/'.join(file_path[-i:])
            result = subprocess.run(['find', str(analysis_src), '-path', f"*/{path}"], capture_output=True)
            if not result.stdout:
                code_path = '/'.join(file_path[1:len(file_path)-i+1])
                break
        if code_path:
            potential_code_paths.append(code_path)
    
    if not potential_code_paths:
        raise Exception("C - No potential code paths found in the compile commands.")
    
    # get the most common path
    freq = {i: potential_code_paths.count(i) for i in set(potential_code_paths)}
    max_count = max(freq.values())
    true_build_src = [i for i in freq if freq[i] == max_count]
    print(f"✅ Potential true build src: {true_build_src}")
    print('--------------------------------------------\n')
    return true_build_src

def get_build_src_java(project_path: Path) -> List[Path]:
    """
    Get the build src path for the Java projects.

    IMPORTANT: It provides you the paths inside "project_path / artifacts / built_src"
    """
    print('\n--------------------------------------------')
    print(f"🔍 Searching for the true build src path...")
    # 1) Get all java files in the `source_root` directory
    analysis_src = project_path / 'artifacts' / 'source_root'
    src_java_files = []
    for root, _, files in os.walk(analysis_src):
        for file in files:
            if file.endswith('.java'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, analysis_src)
                src_java_files.append(relative_path)
    
    # 2) Get all java files in the `built_src` directory
    build_src = project_path / 'artifacts' / 'built_src'
    build_src_java_files = []
    for root, _, files in os.walk(build_src):
        for file in files:
            if file.endswith('.java'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, build_src)
                build_src_java_files.append(relative_path)

    # 3) Compare the two lists to find the most common path
    potential_code_paths = []
    for src_file in tqdm(src_java_files):
        for build_src_file in build_src_java_files:
            if src_file in build_src_file:
                code_path = build_src_file.replace(src_file, '')
                potential_code_paths.append(code_path)
    if not potential_code_paths:
        raise Exception("Java - No potential code paths found.")
    
    # 3) Get the most common path
    freq = {i: potential_code_paths.count(i) for i in set(potential_code_paths)}
    max_count = max(freq.values())
    true_build_src = [i for i in freq if freq[i] == max_count]
    print(f"✅ Potential true build src: {true_build_src}")
    print('--------------------------------------------\n')
    return true_build_src
