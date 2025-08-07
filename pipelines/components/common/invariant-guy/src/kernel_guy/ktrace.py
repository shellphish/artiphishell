#!/usr/bin/env python3
import json
import multiprocessing
import yaml

from os import listdir

from .docker_interact import *
from .kutils import *


def virtme_run(target_dir, kernel_src_dir, script_sh):
    cmd = ' '.join(['virtme-run', 
                    # '--verbose', '--show-boot-console', 
                    '--kimg', f"{kernel_src_dir}/arch/x86/boot/bzImage",
                    "--memory", VIRTME_MEM, "--cpus", VIRTME_CPUS, 
                    "--mods=auto", # Put "use" here if you need to load the right /libs/modules/<KERNEL_VERSION>/build in the GUEST Filesystem
                    #"-a", "kasan.fault=report", 
                    #"-a", "kernel.panic=0", 
                    #"-a", "kernel.panic_on_oops=0",
                    "-a", "kasan.mode=async",
                    "--rwdir", "/work", 
                    "--rwdir", "/out", 
                    "--script-sh", f"'{script_sh}'"])

    print(f'Virtme command:\n 🚀 {cmd}')
    docker_run_custom_command_multiprocessing(target_dir, cmd)


'''
 __   __                              
|  | ___/  |_____________   ____  ____  
|  |/ /\   __\_  __ \__  \ _/ ___\/ __ \ 
|   <  |  |  |  | \// __ \\  \__\  ___/ 
|__|_ \ |__|  |__|  (____  /\___  >___  >
     \/               \/     \/ \/ 
'''
def ktrace(cp_project, poiguy_report, crash_commit, functions_by_file_index, target_dir, target_harness_bin, target_harness_src, kernel_src_dir, benign_inputs_dir, crash_input_path):

    print("Parsing kasan report...")

    crash_workdir = f"{target_dir}/work/crash-workdir"

    os.system(f'rm -rf {crash_workdir}')
    os.system(f'mkdir -p {crash_workdir}')

    benign_seed_dir = f"{crash_workdir}/{BENIGN_SEED_DIR}"
    crash_traces = f"{crash_workdir}/{CRASH_TRACES_DIR}"
    benign_traces = f"{crash_workdir}/{BENIGN_TRACES_DIR}"

    os.system(f'mkdir -p {benign_seed_dir}')
    os.system(f'mkdir -p {crash_traces}')
    os.system(f'mkdir -p {benign_traces}')

    # copy a random selection of MAX_NUM_BENIGN_INPUTS
    os.system(f'cd {benign_inputs_dir} && ls {benign_inputs_dir} | shuf -n {MAX_NUM_BENIGN_INPUTS} | xargs -I {{}} cp {{}} {benign_seed_dir}')

    # copy the crashing input
    os.system(f'cp {crash_input_path} {crash_workdir}/crash.seed')

    with open(functions_by_file_index, "r") as f:
        functions_by_file_index_json = yaml.safe_load(f)

    # Retrieve the harness binary path
    kernel_vm_linux = f'{kernel_src_dir}/vmlinux'

    tracepoints = set()
    tracepoints_to_func = {}
    tracepoints_to_key_index = {}

    for stack_trace in poiguy_report['stack_traces']:
        # Use all the stacktraces available for this report
        for call_loc in stack_trace['call_locations']:
            try:
                func = call_loc['function']
                file = call_loc['relative_file_path']
                loc = call_loc['line_number']
                key_index = call_loc['key_index']
                func_name = call_loc['function_name']
            except Exception as e:
                print(f' 🤸🏻 Skipping frame: {call_loc}')
                continue

            if key_index == None:
                # Filter location not in scope (libraries)
                print(f' 💃🏻 Skipping not in scope library in {file} ')
                continue

            if file in target_harness_src:
                # Filter harness location
                print(f' 🕺🏻 Skipping harness location in {file} ')
                continue
            
            if "LLVM" in func_name:
                # Filter harness location
                print(f' 👯 Skipping LLVM related function ({func_name}) in {file}')
                continue

            tracepoints.add(f"{file}:{loc}")
            tracepoints_to_func[f"{file}:{loc}"] = func_name
            tracepoints_to_key_index[f"{file}:{loc}"] = key_index

    # 👩🏻‍🏫
    # Second, extract the interesting program points from the
    # commits. Here we want to try to put probes on the functions that were modified 
    # in the crashing inputs.

    # Find the cp_source in scope given the crash commit
    cp_source_in_scope = None
    try:
        cp_source_in_scope = cp_project.peek_commit(crash_commit)
    except Exception as e:
        # This should theoretically NEVER happen.
        print(f' 🏃🏻‍♂️ Could not find cp_source in scope given {crash_commit} --> Skipping this')
        print(e)

    num_tracepoints = len(tracepoints)
    
    if cp_source_in_scope:
        
        try:
            cp_source_in_scope_key = cp_source_in_scope[0].key

            # Get the Git repo for this cp_source
            cp_source_repo = cp_project.get_repo(cp_source_in_scope_key)

            print(f'⛏️ Extracting new program points using the crashing commits (cp_source: {cp_source_in_scope_key} | crash commit: {crash_commit})')
            # Get all the file that have been touched by this commit
            files_in_scope = cp_source_repo.commit(crash_commit).stats.files.keys()
            for f_path in files_in_scope:
                full_file_path = cp_source_in_scope_key + "/" + f_path
                file_report = functions_by_file_index_json[full_file_path]
                # For every file in scope, let's extract the blame entries.
                # Every blame entry that points back to the crashing commit can give us
                # some interesing new program points (file:loc)
                # e.g., BlameEntry(commit=<git.Commit "22e7f707e16ab7f6ef8a7e9adbb60b24bde49e27">, 
                #                 linenos=range(26, 28), 
                #                 orig_path='mock_vp.c', 
                #                 orig_linenos=range(23, 25))
                # - linenos represents the lines changed for this file in this commit
                # - if it says (26,28), 26 is NOT included, 28 is INCLUDED.
                for blame_entry in cp_source_repo.blame(cp_source_repo.commit().hexsha, f_path, incremental=True):
                    if blame_entry.commit.hexsha == crash_commit:
                        file_path = blame_entry.orig_path
                        file_locs_range = blame_entry.orig_linenos
                        # One last thing, we need to extract the function name for these lines
                        for loc in range(file_locs_range.start+1, file_locs_range.stop+1):
                            # file_report contains the boundaries of every function!
                            # let's check in which function is our line
                            func_in_scope, key_index = get_func_name(file_report, loc)
                            if func_in_scope == "?":
                                print(f' 💃🏻 Skipping line {loc} with no function. Skipping. ')
                                continue
                            else:
                                tracepoints.add(f"{full_file_path}:{loc}")
                                tracepoints_to_func[f"{full_file_path}:{loc}"] = func_in_scope
                                tracepoints_to_key_index[f"{full_file_path}:{loc}"] = key_index

            if num_tracepoints < len(tracepoints):
                print(f'⛏️ Extracted {len(tracepoints)} program points from the commit report: ')
                for tp in tracepoints:
                    print(f'  💎 {tp}')

        except Exception:
            print(f'🏃🏻‍♂️ Could not extract program points from the commit report. Skipping in shame...')

    # Check if we have any tracepoints to probe
    if len(tracepoints) == 0:
        print(f'💀 No wanted tracepoints. InvGuy ends here.')
        raise KamikazeException()

    
    with open(f"{crash_workdir}/wanted_tracepoints", "w") as f:
        json.dump(list(tracepoints), f)

    # Copy the bash scripts that will execute in the virtme
    print(f'cp /src/kernel_guy/data/in_docker_kprobe.py {crash_workdir}/in_docker_kprobe.py')
    os.system(f"cp /src/kernel_guy/data/in_docker_kprobe.py {crash_workdir}/in_docker_kprobe.py")
    os.system(f'chmod +x {crash_workdir}/in_docker_kprobe.py')
    print(f'cp /src/kernel_guy/data/in_docker_ktrace.py {crash_workdir}/in_docker_ktrace.py')
    os.system(f"cp /src/kernel_guy/data/in_docker_ktrace.py {crash_workdir}/in_docker_ktrace.py")
    os.system(f'chmod +x {crash_workdir}/in_docker_ktrace.py')

    print(f'Starting the tracing!')

    # Make sure the bening input is not panicking the kernel
    # (Hopefully this is not needed during the competition)
    # if TEST_BENIGN_SEEDS:
    #    for benign_input in listdir(benign_seed_dir):
    #        print(f" 🤔😇 Testing benign input {benign_input}")
    #        exitcode, stdout, stderr = docker_run_pov_command(target_dir, target_harness_name, f"{benign_seed_dir}/{benign_input}", timeout=30)
    #        if stdout == "":
    #            print(f" 🚮 Benign input {benign_input} is bad. Skipping.")

    #            # Remove this input from the working directory
    #            print(f"  - rm {benign_seed_dir}/{benign_input}")
    #            os.system(f'rm {benign_seed_dir}/{benign_input}')

    #            # Remove it also from the folder we got from pdt
    #            print(f"  - rm {benign_inputs_dir}/{benign_input}")
    #            os.system(f'rm {benign_inputs_dir}/{benign_input}')
    #        else:
    #            print(f" 🎉 Benign input {benign_input} is good!")

    # first add (and cache) the perf probes
    wanted_tracepoints_at = f"/work/crash-workdir/wanted_tracepoints"
    probes_metadata_at = f"/work/crash-workdir/probes_metadata.json"
    probes_cached_at = f"/work/crash-workdir/probes_cached"
    record_options_cached_at = f"/work/crash-workdir/record_options_cached"
    virtme_run(target_dir, kernel_src_dir, f"cd /work/crash-workdir && ./in_docker_kprobe.py --probes-meta-at {probes_metadata_at} --probes-cached-at {probes_cached_at} --record-options-cached-at {record_options_cached_at} --wanted-tracepoints-at {wanted_tracepoints_at} --perf /shellphish/linux/tools/perf/perf --target-kernel-src {kernel_src_dir} --target-vmlinux {kernel_vm_linux}")

    # confirm that probes were cached
    if not os.path.exists(f"{target_dir}/{probes_metadata_at}"):
        print(f"Probes metadata not found at {target_dir}/{probes_metadata_at}. Did we find any relevant program points?")
        raise KamikazeException()
    elif not os.path.exists(f"{target_dir}/{probes_cached_at}"):
        print(f"Probes not found at {target_dir}/{probes_cached_at}. Did we find any relevant program points?")
        raise KamikazeException()
    elif not os.path.exists(f"{target_dir}/{record_options_cached_at}"):
        #f"Record options not found at {target_dir}/{record_options_cached_at}. Did we find any relevant program points?"
        print(f"Record options not found at {target_dir}/{record_options_cached_at}. Did we find any relevant program points?")
        raise KamikazeException()
    # abort if {target_dir}/{probes_cached_at} is empty
    if os.stat(f"{target_dir}/{probes_cached_at}").st_size == 0:
        print(f' No probes cached in {target_dir}/{probes_cached_at}?!')
        raise KamikazeException()
    
    print(f" 🚀 Running {len(listdir(benign_seed_dir))} benign inputs + 1 crashing input")
    num_benign_inputs = len(listdir(benign_seed_dir))
    if num_benign_inputs == 0:
        print(f' 🤡 Very clowny. No benign inputs in {benign_seed_dir}?!')
        raise KamikazeException()

    with multiprocessing.Pool(NPROC_VAL) as pool:
        jobs = list()
        # append one task for each benign input
        for benign_input in listdir(benign_seed_dir):
            jobs.append((target_dir, kernel_src_dir, f"cd /work/crash-workdir && ./in_docker_ktrace.py --seed-at /work/crash-workdir/{BENIGN_SEED_DIR}/{benign_input} --trace-at /work/crash-workdir/{BENIGN_TRACES_DIR}/{benign_input}.trace --probes-cached-at {probes_cached_at} --record-options-cached-at {record_options_cached_at} --perf /shellphish/linux/tools/perf/perf --target-harness-bin {target_harness_bin}"))
        # append one task for the crashing input
        jobs.append((target_dir, kernel_src_dir, f"cd /work/crash-workdir && ./in_docker_ktrace.py --seed-at /work/crash-workdir/crash.seed --trace-at /work/crash-workdir/{CRASH_TRACES_DIR}/crash.trace --probes-cached-at {probes_cached_at} --record-options-cached-at {record_options_cached_at} --perf /shellphish/linux/tools/perf/perf --target-harness-bin {target_harness_bin}"))

        # run all the tasks
        pool.starmap(virtme_run, jobs)

    return True, "OK", crash_workdir, f"{target_dir}/{probes_metadata_at}", tracepoints_to_func, tracepoints_to_key_index

def get_func_name(function_index_report, loc):
    # function_index_report is a list of dictionaries
    # that describe the boundaries of every function in a given file.
    # TODO: for fast lookup, do this with panda and the csv.
    # e.g.,
    # - end_column: 2
    # - end_line: 132
    # - end_offset: 2798
    # - function_signature: src/nilo-the-force-awakens/nilo-the-force-awakens.c:97:1::int main(int, char **)
    # - start_column: 1
    # - start_line: 97
    # - start_offset: 2208
    for func in function_index_report:
        if func['start_line'] <= loc <= func['end_line']:
            try:
                func_name = func['function_signature'].split('(')[0].split(' ')[-1]
                return func_name, func['function_signature']
            except Exception as e:
                return "?"
    return "?"