
import argparse
import os
import yaml
import json

from shellphish_crs_utils.challenge_project import ChallengeProject

def random_string(length=10):
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def do_c(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_name, target_harness_src, benign_inputs_dir, crash_input_path, output_report_at):

    from c_guy import ctrace, cmine, CRASH_TRACES_DIR, BENIGN_TRACES_DIR

    # First, count the number of benign inputs in the benign_inputs folder.
    available_benign_inputs = len(os.listdir(benign_inputs_dir))
    if available_benign_inputs < num_benign_min:
        # NOTE: here we could bump up the num_benign_min and just wait.
        # for now, we just keep num_benign_min to 1 and just exit if we
        # don't have at least one benign.
        raise ValueError("Not enough benign inputs available. Early exit")

    safe_to_proceed, reason, crash_workdir, probes_metadata_at, tracepoints_to_func,  tracepoints_to_key_index = ctrace(cp_project, poiguy_report, crash_commit, functions_by_file_index, target_dir, target_harness_bin, target_harness_name, target_harness_src, crash_input_path, benign_inputs_dir)
    
    if not safe_to_proceed:
        raise ValueError(f" 👋🏼 ctrace: {reason}")

    try:
        with open(probes_metadata_at, 'r') as f:
            probes_metadata = json.load(f)
    except Exception as e:
        print(f' 🤡 Error loading probes metadata file: {e}')
        raise
    
    crash_traces = f"{crash_workdir}/{CRASH_TRACES_DIR}"
    benign_traces = f"{crash_workdir}/{BENIGN_TRACES_DIR}"

    cmine(target_dir, benign_traces, crash_traces, probes_metadata, tracepoints_to_func, tracepoints_to_key_index, output_report_at)


def do_java(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_name, target_harness_src, target_harness_java_classpath, benign_inputs_dir, crash_input_path, output_report_at):

    from java_guy import jtrace, jmine, CRASH_TRACES_DIR, BENIGN_TRACES_DIR

    # First, count the number of benign inputs in the benign_inputs folder.
    available_benign_inputs = len(os.listdir(benign_inputs_dir))
    if available_benign_inputs < num_benign_min:
        # NOTE: here we could bump up the num_benign_needed and just wait.
        # for now, we just keep num_benign_needed to 1 and just exit if we 
        # don't have at least one benign.
        raise ValueError("Not enough benign inputs available. Early exit")

    safe_to_proceed, reason, crash_workdir, tracepoints_to_func, functions_by_file_index_report = jtrace(cp_project, poiguy_report, crash_commit, functions_by_file_index, target_dir, target_harness_bin, target_harness_name, target_harness_src, target_harness_java_classpath, benign_inputs_dir, crash_input_path, output_report_at)
    
    if not safe_to_proceed:
        raise ValueError(f" 👋🏼 jtrace: {reason}")
    else:
        crash_traces = f"{crash_workdir}/{CRASH_TRACES_DIR}"
        benign_traces = f"{crash_workdir}/{BENIGN_TRACES_DIR}"

        # This dict will store the association between the probename and its
        # location in the source code of the target program.
        #probes_metadata_filepath = f'{crash_workdir}/probes_metadata.json'
        #with open(probes_metadata_filepath, 'r') as f:
        #   probes_metadata = json.load(f)
        jmine(target_dir, benign_traces, crash_traces, tracepoints_to_func, functions_by_file_index_report, functions_by_file_index, output_report_at)

    return True

def do_kernel(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_src, kernel_src_dir, benign_inputs_dir, crash_input_path, output_report_at):

    from kernel_guy import ktrace, kmine

    # target: the folder where we can find the kernel compiled by ourselves (perf and debug symbols enabled)
    # benign_inputs_dir: the folder where we can find the benign inputs (seeds for the kernel harness)
    # crash_input_path: the input that crashed the kernel (seed for the kernel harness)

    # First, count the number of benign inputs in the benign_inputs folder.
    benign_inputs = os.listdir(benign_inputs_dir)
    if len(benign_inputs) < num_benign_min:
        # NOTE: here we could bump up the num_benign_min and just wait.
        # for now, we just keep num_benign_min to 1 and just exit if we
        # don't have at least one benign.
        raise ValueError("Not enough benign inputs available. Early exit")

    # If we are here, we have enough inputs to proceed! Yay! 🎉
    #   probes_metadata: the metadata of the probes we collected during the trace
    #   tracepoints_to_func: the mapping between the tracepoints and the functions they belong to
    safe_to_proceed, reason, crash_workdir, probes_metadata_at, tracepoints_to_func, tracepoints_to_key_index = ktrace(cp_project, poiguy_report, crash_commit, functions_by_file_index, target_dir, target_harness_bin, target_harness_src, kernel_src_dir, benign_inputs_dir, crash_input_path)

    if not safe_to_proceed:
        raise ValueError(f" 😭 ktrace failed: {reason}")

    try:
        with open(probes_metadata_at, 'r') as f:
            probes_metadata = json.load(f)
    except Exception as e:
        print(f' 🤡 Error loading probes metadata file: {e}')
        raise Exception

    # We are ready to mine! ⛏️
    kmine(kernel_src_dir, crash_workdir, probes_metadata, tracepoints_to_func, tracepoints_to_key_index, output_report_at)



'''
.___              ________
|   | _______  __/  _____/ __ __ ___.__.
|   |/    \  \/ /   \  ___|  |  <   |  |
|   |   |  \   /\    \_\  \  |  /\___  |
|___|___|  /\_/  \______  /____/ / ____|
         \/             \/       \/
        [1] Entry point for the invariant-guy
'''
def main():
    argparser = argparse.ArgumentParser(description='inv-guy')

    # Number of benign inputs we want to have before even starting to mine invariants.
    argparser.add_argument('--num-benign-min', type=str, help='number of benign inputs to use for calculating invariants', required=False, default=20)

    # The target dir of the challenge project (as compiled by invguy-build)
    argparser.add_argument('--target-dir', type=str, help='target program', required=True)

    # target-metadata is the metadata of the program, it containts info regarding language etc... (location of 1.yaml)
    argparser.add_argument('--target-metadata', type=str, help='metadata of target program')

    # Benign-inputs is a stream folder containing the benign inputs.
    argparser.add_argument('--benign-inputs', type=str, help='src of crashing input', required=True)

    # Crash-input is the input that crashed the program.
    argparser.add_argument('--crash-input',   type=str, help='bin of crashing input')

    # First crashing commit id when the challenge started to crash
    argparser.add_argument('--crash-commit',   type=str, help='First commit where the challenge started to crash', required=True)
    
    # Metadata folder for the commit modifications
    argparser.add_argument('--functions_by_file_index', type=str, help='Metadata that maps every filename to its functions', required=True)

    # This is the report from the POI guy.
    argparser.add_argument('--poiguy-report', type=str, help='bin of crashing input', required=True, default=None)

    # Output directory for the report.
    argparser.add_argument('--output-report-at', type=str, help='output directory', required=True)

    args = argparser.parse_args()

    target_metadata = args.target_metadata
    num_benign_min = int(args.num_benign_min)
    target_dir = args.target_dir
    benign_inputs_dir = args.benign_inputs
    crash_input_path = args.crash_input
    poiguy_report_at = args.poiguy_report
    crash_commit = args.crash_commit
    functions_by_file_index = args.functions_by_file_index

    cp_project = ChallengeProject(target_dir)

    # FUCK THIS!!!!!!
    os.system("git config --global --add safe.directory '*'")

    output_report_at = args.output_report_at
    # open the yaml file and extract the target
    with open(target_metadata) as yaml_file:
        # load the yaml file
        try:
            target_metadata = yaml.safe_load(yaml_file)
        except yaml.YAMLError as exc:
            raise Exception(" 🤡 Error parsing target metadata yaml file: " + str(exc))

    with open(poiguy_report_at) as poiguy_report_yaml_file:
        # load the yaml file
        try:
            poiguy_report = yaml.safe_load(poiguy_report_yaml_file)
        except yaml.YAMLError as exc:
            raise Exception(" 🤡 Error parsing POI guy report yaml file: " + str(exc))

    # We must have a harness id!
    if not poiguy_report.get('harness_id', None):
        print(" 🤷🏼‍♂️ POI guy report is not for a crash. Aborting.")
        return

    if poiguy_report['detection_strategy'] != 'fuzzing':
        print(" 🤷🏼‍♂️ POI guy report is not from fuzzing. Aborting.")
        return

    target_harness_id = poiguy_report['harness_id']
    target_harness_bin = "/"+target_metadata['harnesses'][target_harness_id]['binary']
    target_harness_name = target_metadata['harnesses'][target_harness_id]['name']
    target_harness_src = "/"+target_metadata['harnesses'][target_harness_id]['source']

    # if is_kernel:
    if target_metadata.get("shellphish", {}).get("known_sources", {}).get("linux_kernel") is not None:
        # In this case, target is the folder containing my kernel build
        # i.e., the folder containing the .config file (root of the kernel)
        kernel_src_dir = "/" + target_metadata["shellphish"]["known_sources"]["linux_kernel"][0]['relative_path']
        print(f'🎁 Project info:\n -target: kernel\n - target_dir: {target_dir}\n - kernel_src_dir: {kernel_src_dir}\n - poiguy_report: {poiguy_report_at}\n - benign_inputs_dir: {benign_inputs_dir}\n - crash_input_path: {crash_input_path}\n -harness name: {target_harness_name}\n - output-report-at {output_report_at}\n')
        do_kernel(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_src, kernel_src_dir, benign_inputs_dir, crash_input_path, output_report_at)
    else:
        target_to_study = target_metadata.get("language", None)
        if target_to_study == "c":
            # target_dir: the folder where we can find the program compiled by ourselves (Dockerfile location)
            # crash_input_dir: the folder where we have the input that crashed the program
            print(f"🎁 Project info:\n target_dir: {target_dir}\n num_benign_min: {num_benign_min}\n target_harness_bin: {target_harness_bin}\n target_harness_name: {target_harness_name}\n benign_inputs_dir: {benign_inputs_dir}\n crash_input_path: {crash_input_path}\n -harness name: {target_harness_name}\n output_report_at: {output_report_at}\n")
            do_c(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_name, target_harness_src, benign_inputs_dir, crash_input_path, output_report_at)
        elif target_to_study == "java":
            print(f"🎁 Project info:\n target_dir: {target_dir}\n num_benign_min: {num_benign_min}\n target_harness_bin: {target_harness_bin}\n target_harness_name: {target_harness_name}\n benign_inputs_dir: {benign_inputs_dir}\n crash_input_path: {crash_input_path}\n -harness name: {target_harness_name}\n output_report_at: {output_report_at}\n")
            
            # given the target_harness_src, we convert it into the classpath.
            # to do so, we split
            target_harness_java_classpath = target_harness_src.replace("/", ".")
            assert(".java." in target_harness_java_classpath)
            target_harness_java_classpath = target_harness_java_classpath.split(".java.")[1]
            target_harness_java_classpath = target_harness_java_classpath.replace(".java", "")
            do_java(cp_project, poiguy_report, crash_commit, functions_by_file_index, num_benign_min, target_dir, target_harness_bin, target_harness_name, target_harness_src, target_harness_java_classpath, benign_inputs_dir, crash_input_path, output_report_at)
        else:
            print(f"Error: target {target_to_study} not supported")
            assert(False)

if __name__ == "__main__":
    main()

