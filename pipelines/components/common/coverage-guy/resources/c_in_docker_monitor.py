import argparse
import os
import shutil
import subprocess
import sys
import time
import random
import string

import yaml
import queue

from collections import defaultdict


TRACING_TIMEOUT = 15
LLVM_PROFDATA_TIMEOUT = 15

BAD_SEEDS = defaultdict(set)


def run_command(cmd, timeout=None):
    try:
        # randomize stdout and stderr filenames because this is run in parallel
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        stdout_filename = f"/tmp/cmd_stdout_{suffix}"
        stderr_filename = f"/tmp/cmd_stderr_{suffix}"

        with open(stdout_filename, "wb") as cmd_stdout, open(stderr_filename, "wb") as cmd_stderr:
            print(f"Running command: {cmd}")
            pid = subprocess.Popen(cmd, shell=True, text=False, stdout=cmd_stdout, stderr=cmd_stderr)
            pid.communicate(timeout=timeout)
            exit_code = pid.returncode

        with open(stdout_filename, "r", encoding='utf-8', errors='replace') as cmd_stdout, open(stderr_filename, "r", encoding='utf-8', errors='replace') as cmd_stderr:
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()
        
        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)

        return exit_code, cmd_stdout_text, cmd_stderr_text
    
    except subprocess.TimeoutExpired:
        print(f" >>> ⏰ Timeout expired for command {cmd} <<<")
        pid.kill()
        
        with open(stdout_filename, "r", encoding='utf-8', errors='replace') as cmd_stdout, open(stderr_filename, "r", encoding='utf-8', errors='replace') as cmd_stderr:
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()
            # Remove files after we read the content
            os.remove(stdout_filename)
            os.remove(stderr_filename)
        return -1, cmd_stdout_text, cmd_stderr_text
    
    except subprocess.CalledProcessError as e:
        print(e)
        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)
        return -1, "", ""

def is_bad_seed(exit_code, stderr, stdout, sanitizers_strings):
    # if any of the sanitizers strings are in the stderr or stdout
    if ( any([s in stderr for s in sanitizers_strings]) or any([s in stdout for s in sanitizers_strings]) ):
        print(f" 🤡 Detected crash in benign input: {exit_code} {stderr} {stdout}")
        return True
    # if "/work/coverage.profraw" is empty
    elif not os.path.exists("/work/coverage.profraw"):
        print(f" 🤡 Detected crash in benign input: coverage.profraw does not exist")
        return True
    elif os.path.getsize("/work/coverage.profraw") == 0:
        print(f" 🤡 Detected crash in benign input: empty coverage.profraw")
        return True
    else:
        return False

def trace_seed(repo_key, repo_type, repo_main, repo_main_metadata, repo_coverage, repo_coverage_full, sanitizers_strings):
    seed_path = f"{repo_main}/{repo_key}"
    seed_meta_path = f"{repo_main_metadata}/{repo_key}"
    coverage_path = f"{repo_coverage}/{repo_key}"
    coverage_full_path = f"{repo_coverage_full}/{repo_key}"
    tmp_path = f"/tmp/{repo_key}"

    try:
        print(f"Tracing new seed {seed_path}")
        sys.stdout.flush()

        shutil.copy(seed_path, f"/work/pov")

        with open(seed_meta_path, "r") as infile:
            metadata = yaml.safe_load(infile)
        # IMPORTANT: cp_harness_binary_path is our fake harness, we need the real one
        harness_bin = "/" + metadata['cp_harness_binary_path'] + "_real"

        # NOTE: unless thera are arguments to Libfuzzer itself (but those should be already exported in the env)
        # this is safe to do. Every arguments to the main of the challenge are passed by the harness to the program
        # under testing.
        cmd = f"{harness_bin} /work/pov"
        
        exit_code, stdout, stderr = run_command(cmd, timeout=TRACING_TIMEOUT)

        if exit_code == -1:
            print(f' 🤡 Fatal error during {cmd}. Skipping seed: {seed_meta_path}')
            return False
        elif exit_code != 0:
            print(f' 🤡 Non-Fatal error during {cmd}. Seed: {seed_meta_path}')
            print(f"{exit_code=}\n{stdout=}{stderr=}")

        # 🛡️: Seed condom in action, if we detect a crash for a 
        #     benigin input, we discard this seed.
        if repo_type == "benign_inputs" and is_bad_seed(exit_code, stderr, stdout, sanitizers_strings):
            print(f' 🙅🏻‍♂️ Seed condom: {seed_path} blocked!')
            return False
        
        # Make sure the coverage file exists
        if not os.path.exists("/work/coverage.profraw"):
            print(f" 🤡 Coverage file /work/coverage.profraw not found")
            return False
        
        # Copy the full report
        # shutil.copy("/work/coverage.profraw", coverage_full_path)

        print(f"Parsing coverage.profraw for {seed_path}")
        sys.stdout.flush()

        # parse the .profraw output and log the covered functions
        # write a tmpfile first, only then copy to the final location -- otherwise if 
        # llvm-profdata writes an empty file and then overwrites it pydatatask will 
        # start syncing the first file
        cmd = f"llvm-profdata show --covered --output {tmp_path} /work/coverage.profraw"
        exit_code, stdout, stderr = run_command(cmd, timeout=LLVM_PROFDATA_TIMEOUT)

        if exit_code == -1:
            print(f' 🤡 Fatal error during {cmd}. Skipping seed: {seed_meta_path}')
            return False
        elif exit_code != 0:
            print(f' 🤡 Non-Fatal error during {cmd}. Seed: {seed_meta_path}')
            print(f"{exit_code=}\n{stdout=}{stderr=}")

        # sort and uniq instead of just copying the file
        with open(tmp_path, "r") as infile:
            covered_functions = set(infile.readlines())
        with open(coverage_path, "w") as outfile:
            outfile.writelines(sorted(covered_functions))

        print(f"Done tracing {seed_path}. Written coverage to {coverage_path}")
        sys.stdout.flush()

        return True
        
    except subprocess.TimeoutExpired:
        print(f"Timeout when tracing {seed_path}")
        sys.stdout.flush()
        return False
    except:
        print(f"Error when tracing {seed_path}")
        sys.stdout.flush()
        return False

###################################################################################################
###################################################################################################
QUEUES = {
    'benign_inputs': queue.Queue(),
    'crashing_inputs': queue.Queue(),
}
def monitor_coverage(pdt_repo_config):
    print(f' 🐎 STARTED C IN DOCKER MONITOR 🐎')
    # INPUTS
    benign_harness_inputs_main_dir = pdt_repo_config['benign_harness_inputs_main_dir']
    benign_harness_inputs_lock_dir = pdt_repo_config['benign_harness_inputs_lock_dir']
    benign_harness_inputs_metadata_main_dir = pdt_repo_config['benign_harness_inputs_metadata_main_dir']
    benign_harness_inputs_metadata_lock_dir = pdt_repo_config['benign_harness_inputs_metadata_lock_dir']
    crashing_harness_inputs_main_dir = pdt_repo_config['crashing_harness_inputs_main_dir']
    crashing_harness_inputs_lock_dir = pdt_repo_config['crashing_harness_inputs_lock_dir']
    crashing_harness_inputs_metadata_main_dir = pdt_repo_config['crashing_harness_inputs_metadata_main_dir']
    crashing_harness_inputs_metadata_lock_dir = pdt_repo_config['crashing_harness_inputs_metadata_lock_dir']
    target_metadatum_path = pdt_repo_config['target_metadatum_path']

    # Open the target_metadatum_path and read the sanitizers strings.
    # We use those to detect harness crashes
    with open(target_metadatum_path, "r") as infile:
        target_metadatum = yaml.safe_load(infile)
    sanitizers_strings = list(target_metadatum['sanitizers'].values())
    sanitizers_strings = set(sanitizers_strings)
    
    sanitizers_strings.add("UndefinedBehaviorSanitizer")

    print(f' 🏥 Sanitizers strings: {sanitizers_strings}')

    # OUTPUTS
    benign_coverages = pdt_repo_config['benign_coverages']
    benign_coverages_full_report = pdt_repo_config['benign_coverages_full_report']
    crashing_coverages = pdt_repo_config['crashing_coverages']
    crashing_coverages_full_report = pdt_repo_config['crashing_coverages_full_report']

    repos = {
        'benign_inputs': (benign_harness_inputs_main_dir, benign_harness_inputs_lock_dir, benign_harness_inputs_metadata_main_dir, benign_harness_inputs_metadata_lock_dir, benign_coverages, benign_coverages_full_report, sanitizers_strings),
        # 'crashing_inputs': (crashing_harness_inputs_main_dir, crashing_harness_inputs_lock_dir, crashing_harness_inputs_metadata_main_dir, crashing_harness_inputs_metadata_lock_dir, crashing_coverages, crashing_coverages_full_report, sanitizers_strings),
    }

    while True:
        for repo_type, (repo_main, repo_lock, repo_metadata_main, repo_metadata_lock, repo_coverage, repo_coverage_full, sanitizers_strings) in repos.items():
            ready_keys = set(os.listdir(repo_main)) & set(os.listdir(repo_metadata_main))
            ready_keys -= set(os.listdir(repo_lock))
            ready_keys -= set(os.listdir(repo_metadata_lock))
            ready_keys -= set(os.listdir(repo_coverage))
            ready_keys -= BAD_SEEDS[repo_type]

            if ready_keys:
                print(f"Found {len(ready_keys)} ready keys for {repo_type}: {list(sorted(ready_keys))[:20]}...")
                sys.stdout.flush()

                for repo_key in ready_keys:
                    print(f"Processing {repo_type}:{repo_key}")
                    sys.stdout.flush()

                    success = trace_seed(repo_key, repo_type, repo_main, repo_metadata_main, repo_coverage, repo_coverage_full, sanitizers_strings)
                    if not success:
                        BAD_SEEDS["benign_inputs"].add(repo_key)

        print("Sleeping for 15 seconds")
        sys.stdout.flush()
        time.sleep(15)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Monitor crashes from pdt and reconstitute them in a crash directory')
    parser.add_argument('pdt_repo_config', type=str, help='Path to the config file for the PDTRepo')
    args = parser.parse_args()

    with open(args.pdt_repo_config, 'r') as f:
        pdt_repo_config = yaml.safe_load(f)

    print(f"Serving the following repo_config: \n{yaml.safe_dump(pdt_repo_config)}")
    sys.stdout.flush()
    
    # monitor_coverage(pdt_repo_config)
    while True:
        try:
            monitor_coverage(pdt_repo_config)
        except Exception as e:
            print(f"Error in monitor_coverage: {e}")
            print("Sleeping for 15 seconds")
            sys.stdout.flush()
            time.sleep(15)
            print("Restarting monitor_coverage")
            sys.stdout.flush()
            continue