#!/usr/bin/env python3

import argparse
import multiprocessing
import os
import subprocess
import re
import json
import random
import string

'''
This script MUST be constructed by the ctrace.py and run inside the CP docker
container with ./run.sh custom 'python in_docker_ctrace.py'.

When this script runs, we have:
  - /work --> the workdir we are using to work on this crash
  - /src  --> the target directory where we can find the CP
  - /out  --> output directory to place the results
'''

NPROC_VAL = int(os.getenv('NPROC_VAL', 1))
NUM_MAX_PROBES = 128


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


def get_tracepoint_vars(res):
    res = res.replace("\t", " ")
    res = res.split("\n")

    pp_vars = []
    grab_vars = False

    for line in res:
        line = line.strip()
        if len(line) == 0:
            continue
        if line.startswith("@") and grab_vars == False:
            grab_vars = True
            continue
        if line.startswith("@") and grab_vars == True:
            # Multiple tracepoint per program point, let's call it
            # a day for now
            return pp_vars
        if grab_vars:
            # Expecting vars now!
            var_type = ' '.join(line.split(" ")[:-1])
            var_name = line.split(" ")[-1]
            pp_vars.append((var_type, var_name))

    pp_vars = list(set(pp_vars))
    return pp_vars


def inspect_program_point(perf, target_harness_bin, tracepoint):
    print(f"- inspecting program point {tracepoint}")

    while True:
        cmd = f"{perf} probe --source /src -x /{target_harness_bin} -V {tracepoint}"
        exit_code, stdout, stderr = run_command(cmd)

        if exit_code == -1:
            print(f'🤡 Error during inspection of {tracepoint}. stderr {stderr}')
            return tracepoint, None
        
        _stderr = stderr.split("\n")

        if stdout == '':

            # Something went wrong during inspection...
            print(f' Error during inspection of program point {tracepoint}')

            if 'Please try to probe at' in stderr:
                # Ambigous tracepoint:
                #  e.g.,
                # This line is sharing the address with other lines.
                #   Please try to probe at lib/dump_stack.c:105 instead.
                #   Failed to find the address of @dump_stack.c:106
                #   Error: Failed to show vars.
                #   Error during inspection of program point dump_stack.c:106
                for line in _stderr:
                    if "Please try to probe at" in line:
                        alternative_tracepoint = line.replace("Please try to probe at ", "")
                        tracepoint = alternative_tracepoint.replace(" instead.", "")
                        if "/" in tracepoint:
                            tracepoint = tracepoint.split("/")[-1]
                        print(f' Retrying inspecting tracepoint {tracepoint}')
                        break
                else:
                    # This is an error that should be definitely fixed.
                    print(f' 🤡 Error recovery for inspecting tracepoints is broken. CLOWN!')
                    assert(False)
            else:
                print(f' 🏃🏻 Unrecoverable error here: {stderr}. Running away.')
                # Dunno how to recover here...
                return tracepoint, None
        else:
            # We inspected the point successfully!
            break

    res = stdout.replace("\t\t(No matched variables)\n", "")

    return tracepoint, get_tracepoint_vars(res)


def add_probe(probe, perf, target_harness_bin):
    print(f' - Working on {probe}')

    probe_name = None
    probe_internal_name = None

    exit_code, stdout, stderr = run_command(f"cat /sys/kernel/tracing/kprobe_events 2>/dev/null | wc -l")
    if exit_code == -1 or not stdout.strip().isdigit():
        print(f'🤡 Failed to count probes. stderr: {stderr}')
        return probe, probe_name, probe_internal_name

    num_probes = int(stdout.strip())
    if num_probes >= NUM_MAX_PROBES:
        print(f'🤡 Too many probes ({num_probes}), skipping probe {probe}')
        return probe, probe_name, probe_internal_name

    try:
        if "/" in probe:
            probe_name = probe.split("/")[-1]
            probe_name = probe_name.split(" ")[0]
        else:
            probe_name = probe.split(" ")[0]

        # 🧑🏻‍⚕️ Sanitization of the names according to the
        # PROBE SYNTAX (see perf man)
        probe_name = probe_name.replace(":", "_")
        probe_name = probe_name.replace(".", "_")
        probe_name = probe_name.replace("(", "_")
        probe_name = probe_name.replace(")", "_")
        probe_name = probe_name.replace(" ", "_")
        probe_name = probe_name.replace("\t", "_")
        probe_name = probe_name.replace("\n", "_")
        probe_name = probe_name.replace("\r", "_")
        probe_name = probe_name.replace("-", "_")

    except Exception as e:
        print(f' 🤡 Error while extracting probe_name from {probe}')
        #print(f'{e}')
        return probe, probe_name, probe_internal_name

    probe_added = False
    unrecoverable_error = False

    try:
        while not probe_added and not unrecoverable_error:
            #print(f'   - Attempting to add {probe}')
            # Adding probe with some simple trial-error
            print(f"- adding probe {probe_name}={probe}")
            cmd = f"{perf} probe --source /src -x /{target_harness_bin} -v --add '{probe_name}={probe}'"
            exit_code, stdout, stderr = run_command(cmd)

            if exit_code == -1:
                raise Exception(f"🤡 Error while adding probe. stderr: {stderr}")

            _stderr = stderr.split("\n")

            if "You can now use it in all perf tools, such as" in stderr:
                # yes, dunno why, but they print to stderr 🤷🏻‍♂️
                for line in _stderr:
                    if "-aR sleep 1" in line:
                        probe_internal_name = line.split(" ")[3]
                        print(f'  ✅ Probe {probe_internal_name} added')

                        probe_added = True
                        break
                else:
                    unrecoverable_error = True
                    continue

            else:
                #print(f' Trying again to add {probe_name}...')
                # Error recovery, get those clowns out of business.
                if "Failed to find the location of the" in stderr:
                    # some fuckery in the varibles retrieved by perf, let's take that variable
                    # out
                    for line in _stderr:
                        if "Failed to find the location of the" in line:
                            match = re.search(r"'([^']+)'", line)
                            if match:
                                # this is the offending variable
                                variable_name = match.group(1)
                                # take it off
                                probe = probe.replace(variable_name, '')
                                break
                    else:
                        print(f'  🤡 Error recovery for adding probes is broken. CLOWN!')
                        assert(False)
                else:
                    # I dunno how to fix
                    print(f'  ☠️ Unrecoverable error adding {probe_name}')
                    #print("===== STDERR =====\n")
                    #print(stderr)
                    #print("====================")
                    unrecoverable_error = True
    except Exception:
        # Just in case, if something gets fucked, go ahead with the loop.
        return probe, probe_name, probe_internal_name
    
    return probe, probe_name, probe_internal_name


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--probes-meta-at", type=str, help="Where to put the metadata related to the probes we add", required=True)
    argparser.add_argument("--probes-cached-at", type=str, help="Where to put the cached probes", required=True)
    argparser.add_argument("--record-options-cached-at", type=str, help="Where to put the cached record options", required=True)
    argparser.add_argument("--wanted-tracepoints-at", type=str, help="Where to find the tracepoints list", required=True)
    argparser.add_argument("--perf", type=str, help="Location of perf", required=True)
    argparser.add_argument("--target-harness-bin", type=str, help="Path to the binary of the harness we are going to use", required=True)
    args = argparser.parse_args()

    PROBES_META_AT = args.probes_meta_at
    PROBES_CACHED_AT = args.probes_cached_at
    RECORD_OPTIONS_CACHED_AT = args.record_options_cached_at
    WANTED_TRACEPOINTS_AT = args.wanted_tracepoints_at
    PERF = args.perf
    TARGET_HARNESS_BIN = args.target_harness_bin

    # clean probes -- just in case
    exit_code, stdout, stderr = run_command(f"{PERF} probe -d '*'")

    if exit_code == -1:
        raise Exception(f"🤡 Error while adding probe. stderr: {stderr}")
    
    # ADD PROBES
    with open(WANTED_TRACEPOINTS_AT, "r") as f:
        wanted_tracepoints = json.load(f)
    print(f'WANTED TRACEPOINTS: ')
    for probe in wanted_tracepoints:
        print(f'- {probe}')

    print("Inspecting program points to find available local variables...")
    all_probes = set()
    with multiprocessing.Pool(NPROC_VAL) as pool:
        for tracepoint, vars in pool.starmap(inspect_program_point, [(PERF, TARGET_HARNESS_BIN, tracepoint) for tracepoint in wanted_tracepoints]):
            if vars:
                vars = " ".join({var_name for var_type, var_name in vars})
                all_probes.add(f"{tracepoint} {vars}")

    print(f"Found {len(all_probes)} relevant program points")
    print("-" * 80)

    if len(all_probes) == 0:
        exit(1)

    all_active_probes = []
    probes_metadata = {}

    with multiprocessing.Pool(NPROC_VAL) as pool:
        for probe, probe_name, probe_internal_name in pool.starmap(add_probe, [(probe, PERF, TARGET_HARNESS_BIN) for probe in all_probes]):
            if probe_name and probe_internal_name:
                all_active_probes.append(probe_internal_name)
                probes_metadata[probe_name] = probe
    record_options = ["-e " + e for e in all_active_probes]
    record_options = " ".join(record_options)

    # SAVE RECORD OPTIONS, PROBES_METADATA, AND PROBES
    with open(RECORD_OPTIONS_CACHED_AT, "w") as f:
        json.dump(record_options, f)
    with open(PROBES_META_AT, "w") as f:
        json.dump(probes_metadata, f)

    exit_code, stdout, stderr = run_command(f"cat /sys/kernel/tracing/uprobe_events > {PROBES_CACHED_AT}")
    
    if exit_code != 0:
        print(f'🤔 Restoring probes exited with: {exit_code}. stderr: {stderr}')

    print(f"Added {len(all_active_probes)} probes (out of {len(all_probes)})")

if __name__ == '__main__':
    print("**** STARTING in_docker_kprobe inside virtme ****")
    print("================== VM INFO ========================")
    print(f"Linux Kernel is: {' '.join(os.uname())}")
    print(f"CPU: {NPROC_VAL} cores")
    print("===================================================")
    
    main()
