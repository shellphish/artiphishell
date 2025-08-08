import os
import sys
import json
import yaml

from .jutils import *
from .docker_interact import *

SKIP_PREFIX = ["com.code_intelligence.jazzer.sanitizers", "java.base/java.lang", "PipelineCommandUtilFuzzer", "PipelineCommandUtilPovRunner"]

def get_in_scope_program_points(cp_project, crash_commit, poiguy_report, target_harness_src, functions_by_file_index):
    print(" 🎷 Parsing Jazzer report...")

    with open(functions_by_file_index, "r") as f:
        functions_by_file_index_json = yaml.safe_load(f)

    tracepoints = set()
    tracepoints_to_func = {}
    tracepoints_to_key_index = {}
    
    for stacktrace in poiguy_report['stack_traces']:
        for call_loc in stacktrace['call_locations']:
            try:
                func_name = call_loc['function_name']
                
                if any(func_name.startswith(prefix) for prefix in SKIP_PREFIX): continue
                
                file = call_loc['source_relative_file_path']
                loc = call_loc['line_number']
                key_index = call_loc['key_index']
                
            except Exception as e:
                print(f' 🤸🏻 Skipping frame: {call_loc}')
                continue

            # 🛡️ 
            # So here we are taking the file path 
            # and stripping off the top folder. That MUST be in the cp_sources.
            # The rest of the path it is safe to use with perf as the tracepoint location
            # This has been discussed with @Lukas on October 2024.
            # The cp_source always comes AFTER the first src/.
            # This has been changed by @Clasm in November 2024.
            cp_source = file.split("/")[1]
            found_cp_source = False
            for cp_src in cp_project.cp_sources:
                if cp_source == cp_src.key:
                    found_cp_source = True

            if not found_cp_source:
                print(f'{file} not in scope. Skipping.')
                continue
            
            # For the tracepoint, we only want the file path without the cp_source
            file_path = file.split("/", 2)[2]

            # OK, let's ignore a bunch of stuff!
            if key_index == None:
                # Filter location not in scope (libraries)
                print(f' 💃🏻 Skipping not in scope library in {file_path} ')
                continue

            if file_path in target_harness_src:
                # Filter harness location
                print(f' 🕺🏻 Skipping harness location in {file_path} ')
                continue
            
            if "Jazzer" in func_name:
                # Filter harness location
                print(f' 👯 Skipping LLVM related function ({func_name}) in {file_path}')
                continue

            tracepoints.add(f"{file_path}:{loc}")

            # e.g., io.jenkins.plugins.UtilPlug.UtilMain:doexecCommandUtils
            if ":" not in func_name:
                # 🛡️ heck this.
                continue
            
            try:
                function_class = func_name.split(":")[0]
                func_name = func_name.split(":")[1]
            except Exception as e:
                print(f'🤡 Clowned it up during parsing of {func_name} when recovering tracing points. Skipping.')
                continue

            tracepoints_to_func[f"{file_path}:{loc}"] = function_class + "." + func_name
            tracepoints_to_key_index[f"{file_path}:{loc}"] = key_index

    print(f'⛏️ Extracted {len(tracepoints)} program points from the stack trace: ')
    for tp in tracepoints:
        print(f'  💎 {tp}')

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
        print(f'    => Error: {e}')

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
                if full_file_path not in functions_by_file_index_json:
                    continue
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

                                cp_source = full_file_path.split("/")[1]
                                found_cp_source = False
                                
                                for cp_src in cp_project.cp_sources:
                                    if cp_source == cp_src.key:
                                        found_cp_source = True
                                
                                if not found_cp_source:
                                    print(f'{full_file_path} not in scope. Skipping.')
                                    continue
                                
                                file_path = full_file_path.split("/", 2)[2]

                                tracepoints.add(f"{file_path}:{loc}")
                                tracepoints_to_func[f"{file_path}:{loc}"] = func_in_scope
                                tracepoints_to_key_index[f"{file_path}:{loc}"] = key_index

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

    return tracepoints, tracepoints_to_func, tracepoints_to_key_index

def jtrace(cp_project, poiguy_report, crash_commit, functions_by_file_index, target_dir, target_harness_bin, target_harness_name, target_harness_src, target_harness_java_classpath, benign_inputs_dir, crash_input_path, output_report_at):
    """
    Trace the crash and benign inputs
    """
    # Create the crash workdir
    crash_workdir = f"{target_dir}/work/crash-workdir"
    os.system(f'rm -rf {crash_workdir}')
    os.system(f'mkdir -p {crash_workdir}')
    
    # Creates the folder for the inputs
    # NOTE: these folders are available in the target container
    crash_seed_dir = f"{crash_workdir}/{CRASH_SEED_DIR}"
    benign_seed_dir = f"{crash_workdir}/{BENIGN_SEED_DIR}"
    crash_traces = f"{crash_workdir}/{CRASH_TRACES_DIR}"
    benign_traces = f"{crash_workdir}/{BENIGN_TRACES_DIR}"

    os.system(f'mkdir -p {crash_seed_dir}')
    os.system(f'mkdir -p {benign_seed_dir}')
    os.system(f'mkdir -p {crash_traces}')
    os.system(f'mkdir -p {benign_traces}')

    # copy all the inputs
    os.system(f'cp {crash_input_path} {crash_seed_dir}/c000.seed')
    # os.system(f'cp {benign_inputs_dir}/* {benign_seed_dir}')
    os.system(f'cd {benign_inputs_dir} && ls {benign_inputs_dir} | shuf -n {MAX_NUM_BENIGN_INPUTS} | xargs -I {{}} cp {{}} {benign_seed_dir}')

    ############################################
    # EXTRACT PROGRAM POINTS FROM FUZZER REPORT
    ############################################

    # We need this to extract the program points from the ASAN report
    # 💡 FIXME: to make this faster, we could just add this "in scope program points" to the
    # in_docker_ctrace.py
    tracepoints, tracepoints_to_func, tracepoints_to_key_index = get_in_scope_program_points(cp_project, crash_commit, poiguy_report, target_harness_src, functions_by_file_index)

    # REMEMBER THIS!
    #workdir = f"{target_dir}/work/crash-{crash_id}"

    print(f"Found {len(tracepoints)} tracepoints")
    for t in tracepoints:
        print(f' -> t: {t}')
    print("-" * 80)

    # Craft the python script that will run in the docker container
    # to add the probes and trace the inputs
    with open(f"/src/java_guy/data/in_docker_jtrace.py", "r") as f:
        tracer_script = f.read()

    # Fill up the placeholders
    tracer_script = tracer_script.replace("<BENIGN_SEEDS_AT>",  f"/work/crash-workdir/benign_inputs/")
    tracer_script = tracer_script.replace("<BENIGN_TRACES_AT>", f"/work/crash-workdir/benign_traces_dir/")
    tracer_script = tracer_script.replace("<CRASH_SEEDS_AT>",   f"/work/crash-workdir/crashing_inputs/")
    tracer_script = tracer_script.replace("<CRASH_TRACES_AT>",  f"/work/crash-workdir/crash_traces_dir/")
    tracer_script = tracer_script.replace("<PROBES_META_AT>",   f"/work/crash-workdir/probes_metadata.json")
    tracer_script = tracer_script.replace("<TARGET_HARNESS_NAME>",  target_harness_name)
    tracer_script = tracer_script.replace("<TARGET_HARNESS_CLASSPATH>",  target_harness_java_classpath)
    tracer_script = tracer_script.replace("<TARGET_HARNESS_JAR>",  target_harness_bin)

    # Drop it in the /work folder for the CP target to use
    with open(f"{crash_workdir}/in_docker_jtrace.py", "w") as f:
        f.write(tracer_script)

    # template the jazzer_btrace for /classpath/jazzer/jazzer
    with open(f"/src/java_guy/data/jazzer_btrace", "r") as f:
        fake_jazzer = f.read()

    # dump the traceponts_to_func to a file to be available by the in_docker_jtrace
    with open(f"{crash_workdir}/tracepoints_to_func", "w") as f:
        json.dump(tracepoints_to_func, f)

    # Fill up the placeholders
    fake_jazzer = fake_jazzer.replace("<HARNESS_JAR_PATH>",  target_harness_bin)
    fake_jazzer = fake_jazzer.replace("<HARNESS_NAME_FULL_JAVA_NAMESPACE>", target_harness_java_classpath)

    # Drop it in the /work folder for the CP target to use
    with open(f"{crash_workdir}/jazzer_btrace", "w") as f:
        f.write(fake_jazzer)
    os.system(f'chmod +x {crash_workdir}/jazzer_btrace')

    print(f'Starting the tracing!')

    pov = f"{target_dir}/work/pov"
    with open(pov, "w") as f:
        f.write("known-pov-contents\n")

    # 🏃🏻 RUN_POV (BENIGNS)
    exit_code, stdout, stderr = docker_run_pov_command(target_dir, target_harness_name, pov)

    print("Tracing done!")

    # Check if there exist a file with size != 0 in the crash_traces folder
    with open(f"{crash_workdir}/crash_traces_dir/c000.seed.trace", "r") as f:
        data = f.read()
    
    # Very cheap way to check for bs traces
    if len(data) == 0 or "ppt_type" not in data:
        return False, "Crashing seed didn't work 🤡", crash_workdir, tracepoints_to_func, tracepoints_to_key_index
    
    return True, "OK", crash_workdir, tracepoints_to_func, tracepoints_to_key_index

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
                func_signature = func['function_signature']
                #  🚁 
                class_name = '.'.join(func_signature.split('::')[-1].split()[0].split('.')[:-1])
                func_name = func_signature.split('(')[0].split(' ')[-1]
                full_func_name = class_name + "." + func_name 
                # For java, the func name we are gonna use is clazz:method
                return full_func_name, func['function_signature']
            except Exception as e:
                return "?", "?"
    return "?", "?"
