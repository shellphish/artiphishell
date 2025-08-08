import pathlib
import subprocess

def collect_coverage_in_docker(harness_binary_path: pathlib.Path, target_source_path: pathlib.Path):
    ''' Runs the coverage collection inside of the docker container.
        Outputs will be stored in /work/coverage. Input files need to be in /work/inputs
    :param harness_binary_path: the path to the harness binary relative to the target source folder e.g. out/harness_name
    :param target_src_path: the path to the target source folder (grammar_guy_build.built_target)
    '''
    print_info(f"GG (collect_coverage_in_docker): Coverage collected on: {str(target_source_path / harness_binary_path)}")
    output = subprocess.run(['./run.sh', 'custom', '/shellphish/collect_coverage.sh', f'{str(harness_binary_path)}'], 
                            cwd=str(target_source_path), text=True, capture_output=True)
    print(output.stdout, output.stderr)
    if output.returncode != 0: 
        raise subprocess.CalledProcessError("Could not run collect coverage in docker container", output.stderr)
    
    print_goodboi("GG (collect_coverage_in_docker): Dockerized coverage collection completed")
    
def generate_coverage_report(current_iteration: pathlib.Path, harness_binary_path: pathlib.Path, target_source_path: pathlib.Path):
    ''' Generate the coverage report given the coverage collected by using collect_coverage_in_docker
    :param current_iteration: the path to the current iteration folder (can be fixed if no separation of cov_reports needed)
    :param harness_binary_path: the path to the harness binary relative to the target source folder e.g. out/harness_name
    :param target_src_path: the path to the target source folder (grammar_guy_build.built_target)
    '''
    print_info(f"GG (generate_coverage_report): Generating coverage report for iteration {current_iteration}")
    output = subprocess.run(['./run.sh', 'custom', '/shellphish/generate_function_coverage_report.sh',  
                        f'{str(current_iteration)}', 
                        f'{str(harness_binary_path)}'],
                        cwd=str(target_source_path),
                        text=True, capture_output=True)
    # print(output.stdout, output.stderr)
    if output.returncode!= 0:
        raise subprocess.CalledProcessError("Could not generate coverage report", output.stderr)
    
    
def print_warn(text):
    ''' Print text in red'''
    print(f"\033[91m{text}\033[0m")

def print_goodboi(text):
    ''' Print text in green'''
    print(f"\033[92m{text}\033[0m")

def print_info(text):
    ''' Print text in blue'''
    print(f"\033[94m{text}\033[0m")