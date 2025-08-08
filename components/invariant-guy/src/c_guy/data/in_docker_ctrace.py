#!/usr/bin/env python3

import argparse
import os
import subprocess
import json
import random
import string
import yaml

'''
This script MUST be constructed by the ctrace.py and run inside the CP docker
container with ./run.sh custom 'python in_docker_ctrace.py'.

When this script runs, we have:
  - /work --> the workdir we are using to work on this crash
  - /src  --> the target directory where we can find the CP
  - /out  --> output directory to place the results
'''

TRACE_TIMEOUT = 60


def run_command(cmd, timeout=None):
    try:
        # randomize stdout and stderr filenames because this is run in parallel
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        stdout_filename = f"/tmp/cmd_stdout_{suffix}"
        stderr_filename = f"/tmp/cmd_stderr_{suffix}"

        with open(stdout_filename, "wb") as cmd_stdout, open(stderr_filename, "wb") as cmd_stderr:
            #print(f"Running command: {cmd}")
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
    

def trace_input(f, record_options, perf, target_harness_bin_real, trace_at):
    # target_harness_bin_real is the path to the REAL harness binary
    print(f" 🔬 Tracing harness input {f}")
    #print("-"*30)

    # 🐸 NOTE: Here it is safe to simply call the harness binary + input because we:
    #  1- Called this script via run.sh run_pov
    #  2- The harness binary is harnessed with libfuzzer, any arguments necessary to the 
    #     program to run MUST be setup by the harness itself.
    #  3- Any argument passed to the LibFuzzer itself it is accessed through and ENV var.
    cmd = f"DIR=$(mktemp -d /tmp/perf-XXXXXXXX); {perf} record --no-buffering --no-delay --mmap-pages 32M {record_options} -o $DIR/perf.data -q {target_harness_bin_real} {f}; {perf} script -i $DIR/perf.data 2>&1 | tee {trace_at}; rm -rf $DIR"
    exit_code, stdout, stderr = run_command(cmd, timeout=TRACE_TIMEOUT)
    
    if exit_code == -1:
        print(f'🤡 Clowned it up while tracing input {f}')

    if exit_code != 0:
        print(f'🤔 trace_input cmd exited with: {exit_code}. stderr: {stderr}')

    #print("-"*30)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--ctrace-config", type=str, help="Path to the ctrace config file", required=True)
    args = argparser.parse_args()

    CTRACE_CONFIG = args.ctrace_config

    # Load the config!
    with open(CTRACE_CONFIG, 'r') as f:
        ctrace_config = yaml.safe_load(f)

    TARGET_HARNESS_NAME_REAL = ctrace_config['harness_real_name']
    TARGET_HARNESS_PATH_REAL = ctrace_config['harness_real_path']
    PERF = ctrace_config['perf']
    PROBES_CACHED_AT = ctrace_config['probes_cached_at']
    RECORD_OPTIONS_CACHED_AT = ctrace_config['record_options_cached_at']
    SEEDS_AT = ctrace_config['seeds_at']
    TRACES_AT = ctrace_config['traces_at']

    # clean probes -- just in case
    exit_code, stdout, stderr = run_command(f"{PERF} probe -d '*'")
    if exit_code != 0:
        print(f"🤔 cmd ({PERF} probe -d '*') returned with exit_code: {exit_code}. stderr: {stderr}")
    
    # TRY TO RESTORE PROBES
    try:
        # if PROBES_CACHED_AT exists, restore it to /sys/kernel/tracing/uprobe_events
        assert os.path.isfile(PROBES_CACHED_AT) and os.path.isfile(RECORD_OPTIONS_CACHED_AT)

        # count and restore probes from PROBES_CACHED_AT
        with open(PROBES_CACHED_AT, "r") as f:
            num_probes = len(f.readlines())
            if not num_probes:
                raise Exception("No probes restored. Aborting.")
            
            exit_code, stdout, stderr  = run_command(f"cat {PROBES_CACHED_AT} > /sys/kernel/tracing/uprobe_events")
            if exit_code == -1:
                raise Exception(f"🤡 Error while restoring cached probes: {stderr}")
            
            if exit_code != 0:
                print(f'🤔 Restoring probes cache exited with: {exit_code}. stderr: {stderr}')
            
            print(f"Restored {num_probes} probes from {PROBES_CACHED_AT}")
            print("-" * 80)
        
        # restore record options
        with open(RECORD_OPTIONS_CACHED_AT, "r") as f:
            record_options = json.load(f)

        # TRACE (WITH RESTORED PROBES)
        print(f"Tracing...")

        for seed in os.listdir(SEEDS_AT):
            if "_real" not in TARGET_HARNESS_NAME_REAL:
                # 🤣 AVOID FORK-BOMBING. #True story.
                assert(False)
            trace_input(f"{SEEDS_AT}/{seed}", record_options, PERF, TARGET_HARNESS_PATH_REAL, f"{TRACES_AT}/{seed}.trace")

    except Exception as e:
        print(f"Error while restoring cached probes: {e}")
        exit(1)


if __name__ == '__main__':
    print("**** STARTING in_docker_ctrace inside ****")
    main()
