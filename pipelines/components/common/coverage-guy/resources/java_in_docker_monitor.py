import argparse
import os
import shutil
import subprocess
import sys
import time
import random
import string
import shlex

import yaml
import queue

from lxml import etree
from collections import defaultdict


TRACING_TIMEOUT = 45
JACOCO_TIMEOUT = 15

BAD_SEEDS = defaultdict(set)

JAZZER_ARGS = None


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

def get_covered_methods(xml_file):

    print(f' 🤸🏻 Loading coverage XML file...')
    # check if the file exists
    if not os.path.exists(xml_file):
        print(f"Error: File '{xml_file}' not found")
        return False, None

    try:
        # Parse the XML document
        tree = etree.parse(xml_file)
        class_nodes = tree.xpath('//class[./method/counter[@type="LINE" and @covered>0]]')
        combined_names = set()

        print(f' 🤸🏻 Extracting functions covered by input')

        # Iterate through each class node
        for class_node in class_nodes:
            class_name = class_node.get('name').replace("/", ".")
            # Get method nodes within the class node that have covered lines
            method_nodes = class_node.xpath('./method[counter[@type="LINE" and @covered>0]]')
            for method_node in method_nodes:
                method_name = method_node.get('name')
                combined_name = f"{class_name}:{method_name}"
                combined_names.add(combined_name)

        return True, combined_names
    except Exception as e:
        print(f" 🤡 Error while parsing XML")
        return False, None


def is_bad_seed(exit_code, stderr, stdout, sanitizers_strings):
    # if exit_code != 0 and any of the sanitizers strings are in the stderr or stdout
    if any([s in stderr for s in sanitizers_strings]) or any([s in stdout for s in sanitizers_strings]):
        print(f" 🤡 Detected crash in benign input: {exit_code} {stderr} {stdout}")
        return True
    # if "/work/jazzer.cov" is empty
    elif not os.path.exists("/work/jazzer.cov"):
        print(f" 🤡 Could not find /work/jazzer.cov")
        return True
    elif os.path.getsize("/work/jazzer.cov") == 0:
        print(f" 🤡 The report /work/jazzer.cov is empty")
        return True
    else:
        return False

def trace_seed(repo_key, repo_type, repo_main, repo_main_metadata, repo_coverage, repo_coverage_full, sanitizers_strings):
    seed_path = f"{repo_main}/{repo_key}"
    seed_meta_path = f"{repo_main_metadata}/{repo_key}"
    coverage_path = f"{repo_coverage}/{repo_key}"
    coverage_full_path = f"{repo_coverage_full}/{repo_key}"

    try:
        print(f"Tracing new seed {seed_path}")
        sys.stdout.flush()

        shutil.copy(seed_path, f"/work/pov")

        with open(seed_meta_path, "r") as infile:
            metadata = yaml.safe_load(infile)

        # 🎷 Let's run the seed with the provided harness. 
        # This is basically running jazzer with the coverage option.
        # The result of this command is a .exec file in /work/jazzer.cov
        jazzer_cov_cmd = shlex.join(['/classpath/jazzer/jazzer_cov', *JAZZER_ARGS])
        exit_code, stdout, stderr = run_command(jazzer_cov_cmd, timeout=TRACING_TIMEOUT)

        if exit_code == -1:
            print(f' 🤡 Fatal error during {jazzer_cov_cmd}. Skipping seed: {seed_meta_path}')
            return False
        elif exit_code != 0:
            print(f' 🤡 Non-Fatal error during {jazzer_cov_cmd}. Seed: {seed_meta_path}')
            print(f"{exit_code=}\n{stdout=}{stderr=}")

        # 🛡️: Seed condom in action, if we detect a crash here, we discard this seed
        if repo_type == "benign_inputs" and is_bad_seed(exit_code, stderr, stdout, sanitizers_strings):
            print(f' 🙅🏻‍♂️ Seed condom: {seed_path} blocked!')
            return False

        # We need to locate the classes for this harness.
        # We are using the location of the jar.
        # (We extracted all the .jars in that folder at building time)
        # Our modified version of jacococli just ignore any duplication 
        # of the classes names.
        #  See https://www.jacoco.org/jacoco/trunk/doc/faq.html
        #  "Why do I get the error "Can't add different class with same name"?"
        harness_name = metadata['cp_harness_name']
        harness_classes = "/work/harnesses_classes/" + harness_name

        # ☕️ Now, we use jacococli to extract the coverage report from the .dump file
        # The jacococli jar is in /shellphish.
        # If, for any reason, the previous cmd failed, this is gonna fail too. 
        # This is fine, we will check at the very end.
        jacoco_cmd  = "java -jar /shellphish/coverageguy/my_jacococli.jar report /work/jazzer.cov "
        jacoco_cmd += "--xml /work/jazzer.cov.xml "
        jacoco_cmd += f"--classfiles {harness_classes} "
        exit_code, stdout, stderr = run_command(jacoco_cmd, timeout=JACOCO_TIMEOUT)

        if exit_code == -1:
            print(f' 🤡 Fatal error during {jacoco_cmd}. Skipping seed: {seed_meta_path}')
            return False
        elif exit_code != 0:
            print(f' 🤡 Non-Fatal error during {jacoco_cmd}. Seed: {seed_meta_path}')
            print(f"{exit_code=}\n{stdout=}{stderr=}")

        coverage_xml_report_at = f"/work/jazzer.cov.xml"
        # Make sure the coverage file exists
        if not os.path.exists(coverage_xml_report_at):
            print(f" 🤡 Coverage file {coverage_xml_report_at} not found")
            return False

        # Copy the full XML report to the full_report directory!
        # This is currently done only for Java to support the 
        # QuickSeed component 🌱⚡️
        # shutil.copy(coverage_xml_report_at, coverage_full_path)

        ret, covered_functions = get_covered_methods(coverage_xml_report_at)
        if not ret:
            return False
        
        # Sort the set of strings
        covered_functions = sorted(covered_functions)
        # Write every function name on a newline
        with open(coverage_path, "w") as outfile:
            outfile.writelines([f"{line}\n" for line in covered_functions])

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
    print(f' 🐎 STARTED JAVA IN DOCKER MONITOR 🐎')
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

                for key in ready_keys:
                    print(f"Processing {repo_type}:{key}")
                    sys.stdout.flush()

                    success = trace_seed(key, repo_type, repo_main, repo_metadata_main, repo_coverage, repo_coverage_full, sanitizers_strings)
                    if not success:
                        BAD_SEEDS[repo_type].add(key)

        print("Sleeping for 15 seconds")
        sys.stdout.flush()
        time.sleep(15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor crashes from pdt and reconstitute them in a crash directory')
    parser.add_argument('--jazzer-args', nargs=argparse.REMAINDER, help='Arguments to pass to the harness')
    args = parser.parse_args()

    JAZZER_ARGS = args.jazzer_args
    PDT_REPO_CONFIG = "/work/monitor_config.yaml"

    with open(PDT_REPO_CONFIG, 'r') as f:
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