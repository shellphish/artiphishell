#!/usr/bin/env python3

import argparse
import os
import subprocess
import json
import random
import string

'''
This script MUST be constructed by the ktrace.py and run inside the CP docker
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


def trace_input(f, record_options, perf, target_harness_bin, trace_at):
    print(f" 🔬 Tracing harness input {f}")
    print("-"*30)

    cmd = f"DIR=$(mktemp -d /tmp/perf-XXXXXXXX); {perf} record --no-buffering --no-delay --mmap-pages 32M {record_options} -o $DIR/perf.data -q {target_harness_bin} {f}; {perf} script -i $DIR/perf.data 2>&1 | tee {trace_at}; rm -rf $DIR"
    exit_code, stdout, stderr = run_command(cmd, timeout=TRACE_TIMEOUT)

    if exit_code == -1:
        print(f'🤡 Failed to trace {f}...')

    if exit_code != 0:
            print(f'🤔  perf record exited with: {exit_code}. stderr: {stderr}')

    print("-"*30)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--seed-at", type=str, help="Where to find seeds", required=True)
    argparser.add_argument("--trace-at", type=str, help="Where to put traces", required=True)
    argparser.add_argument("--probes-cached-at", type=str, help="Where to put the cached probes", required=True)
    argparser.add_argument("--record-options-cached-at", type=str, help="Where to put the cached record options", required=True)
    argparser.add_argument("--perf", type=str, help="Location of perf", required=True)
    argparser.add_argument("--target-harness-bin", type=str, help="Path to the binary of the harness we are going to use", required=True)
    args = argparser.parse_args()

    SEED_AT = args.seed_at
    TRACE_AT = args.trace_at
    PROBES_CACHED_AT = args.probes_cached_at
    RECORD_OPTIONS_CACHED_AT = args.record_options_cached_at
    PERF = args.perf
    TARGET_HARNESS_BIN = args.target_harness_bin

    # clean probes -- just in case
    run_command(f"{PERF} probe -d '*'")
    
    # TRY TO RESTORE PROBES
    try:
        # if PROBES_CACHED_AT exists, restore it to /sys/kernel/tracing/kprobe_events
        assert os.path.isfile(PROBES_CACHED_AT) and os.path.isfile(RECORD_OPTIONS_CACHED_AT)

        # count and restore probes from PROBES_CACHED_AT
        with open(PROBES_CACHED_AT, "r") as f:
            num_probes = len(f.readlines())
            if not num_probes:
                raise Exception("🤡 No probes restored. Aborting.")
            
            exit_code, stdout, stderr = run_command(f"cat {PROBES_CACHED_AT} > /sys/kernel/tracing/kprobe_events")
            
            if exit_code == -1:
                raise Exception(f"🤡 Failed to restore probes: {stderr}")

            if exit_code != 0:
                    print(f'🤔  Restoring probes exited with: {exit_code}. stderr: {stderr}')
            
            print(f"Restored {num_probes} probes from {PROBES_CACHED_AT}")
            print("-" * 80)
        
        # restore record options
        with open(RECORD_OPTIONS_CACHED_AT, "r") as f:
            record_options = json.load(f)

        # TRACE (WITH RESTORED PROBES)
        print(f"Tracing...")
        trace_input(SEED_AT, record_options, PERF, TARGET_HARNESS_BIN, TRACE_AT)
        return
        
    except Exception as e:
        print(f"🤡 Error while restoring cached probes: {e}")
        exit(1)


if __name__ == '__main__':
    print("**** STARTING in_docker_ktrace inside virtme ****")
    print("================== VM INFO ========================")
    print(f"Linux Kernel is: {' '.join(os.uname())}")
    print("===================================================")
    
    main()
