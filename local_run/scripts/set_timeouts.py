#!/usr/bin/env python3

from ruamel.yaml import YAML
import os
import pathlib
import shutil
import sys

FUZZER_YAMLS = [
    "components/aflplusplus/pipeline.yaml",
    "components/aijon/pipeline.yaml",
    "components/jazzer/pipeline.yaml"
]

def make_a_backup(file_path):
    """
    Create a backup of the given file.
    """
    backup_path = file_path.with_suffix('.bak')
    shutil.copy(file_path, backup_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python set_timeouts.py <timeout-in-minutes>")
        sys.exit(1)
        
    try:
        timeout = int(sys.argv[1])
    except ValueError:
        print("Error: Timeout must be an integer.")
        sys.exit(1)    
    
    # get the current file path and it's parent
    root_path = pathlib.Path(__file__).parent.parent.parent
    
    # Load the YAML files
    yaml_ruamel = YAML()
    yaml_ruamel.preserve_quotes = True

    for yaml_file in FUZZER_YAMLS:
        yaml_path = root_path / yaml_file 
        make_a_backup(yaml_path)  # Create a backup before modifying
        with open(yaml_path, 'r') as file:
            data = yaml_ruamel.load(file)

        # Update the timeouts
        for job_name, job in data['tasks'].items():
            if 'timeout' in job:
                job['timeout']['minutes'] = timeout
                print(f"Updated timeout for {job_name} to {timeout} minutes.")
        # # Write the updated YAML back to the file
        with open(yaml_path, 'w') as file:
            yaml_ruamel.dump(data, file)
