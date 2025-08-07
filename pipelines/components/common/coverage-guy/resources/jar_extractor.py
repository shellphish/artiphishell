

import argparse
import os
import json
import random
import subprocess
import string
import shlex
import re

# This is gonna be accessed from the java_monitor when using 
# jacococli. Specifically, the --classfiles is gonna point there
# for the resolution of the coverage report.
SAFE_CLASSES_AT = "/work/harnesses_classes/"

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


"""
This script extracts the classes for all the jars in scope!
NOTE: THIS MUST BE EXECUTED AFTER WE BUILT THE CALLENGE BECAUSE 
WE NEED THE JARS IN SCOPE TO BE IN THE CONTAINER.
"""
def main():

    print("""
    _____ _                    _____        _              _             
    / ____| |                  |  __ \\    | |            | |            
    | |    | | ___  _ __   __ _| |__) |__ | |_   _  __ _ | |_   ___  ___ 
    | |    | |/ _ \\| '_ \\ / _` |  ___/ _ \\| | | | |/ _` || __| / _ \\/ __|
    | |____| | (_) | | | | (_| | |  | (_) | | |_| | (_| || |_ |  __/\\__ \\
    \\_____|_|\\___/|_| |_|\\__, |_|   \\___/|_|\\__,_|\\__,_| \\__| \\___||___/
                        __/ |                                          
                        |___/                                           
    """)

    arg_parser = argparse.ArgumentParser(description='Find duplicate classes in JAR files')
    
    arg_parser.add_argument('--jazzer-args', nargs=argparse.REMAINDER, help='Arguments to pass to the harness')
    args = arg_parser.parse_args()

    JAZZER_ARGS = args.jazzer_args
    ANTLR4_REPORT = "/work/antlr4_index.json"

    # create the folder if it does not exist 
    if not os.path.exists(SAFE_CLASSES_AT):
        os.makedirs(SAFE_CLASSES_AT)

    with open(ANTLR4_REPORT, 'r') as f:
        antlr4_report = json.load(f)
    keys = antlr4_report.keys()

    # Extract the last part after '::' from each key
    pats = list(map(lambda x: x.split('::')[-1], keys))

    # Extract the first part before the space from each element in pats
    val = list(map(lambda x: x.split(' ')[0], pats))

    # Split each element in val by '.' and join all but the last part with '.'
    classes_in_scope = set(map(lambda x: '/'.join(x.split('.')[:-1]), val))

    print(f' 🚁 There are {len(classes_in_scope)} classes in scope!')

    # Create a fake file 
    with open("/work/pov", "w") as f:
        f.write("This is a random file")

    jar_in_scope = {}
    pattern = r'/[^\s:]+'

    # Basically, at the end of this loop, we are gonna have, for every harness, 
    # a folder in /work/harnesses_classes/<HARNESS_NAME> with all the .classes 
    # in scope for the coverage.
    harness_name = os.getenv("CP_HARNESS_NAME")
    harness_artifact = os.getenv("CP_HARNESS_BINARY_PATH")

    # if the harness artifacts does not starts with "/", add it
    if not harness_artifact.startswith("/"):
        harness_artifact = "/"+harness_artifact
    harness_artifacts_folder = os.path.dirname(harness_artifact)

    print(f' Analyzing classes for {harness_name}')
    print(f'    - harness_artifact: {harness_artifact}')
    print(f'    - harness_artifacts_folder: {harness_artifacts_folder}')

    jar_in_scope[harness_name] = set()

    cmd = shlex.join(['/classpath/jazzer/jazzer_dump', *JAZZER_ARGS])
    exit_code, stdout, stderr = run_command(cmd)

    if exit_code == -1:
        print(f' 🤡 Fatal error during jazzer pre-check. Skipping harness {harness_name}')
        return False
    elif exit_code != 0:
        print(f' 🤡 Non-Fatal error during jazzer pre-check. Harness: {harness_name}')
        print(f"{exit_code=}\n{stdout=}{stderr=}")

    folders_with_jars = set()
    
    if "R.I.P. Classpath component '--cp' is missing" in stdout or \
            "R.I.P. Classpath component '--cp' is missing" in stderr:
        # YOLO-ing
        print(f'🤷🏻‍♂️ No --cp passed to jazzer. YOLO-ing it')
        folders_with_jars.add(harness_artifacts_folder)
    else:
        matches = re.findall(pattern, stdout)
        try:
            for m in matches:
                if "shellphish" in m:
                    # our shit
                    continue
                if m.endswith(".jar"):
                    # add the directory name in which m is to the 
                    # folders with jars set
                    folders_with_jars.add(os.path.dirname(m))
        except Exception as e:
            print(f'😡 Something went wrong while processing {m}. Continue...')
    
    # Now we know whera are all the JARs in scope!
    #print(f' 🧭 Jars in scope are in: ')
    #for fwj in folders_with_jars:
    #    print(f' - {fwj}')

    # create the safe classes folder for this harness
    safe_classes_folder = f"{SAFE_CLASSES_AT}/{harness_name}/"
    os.makedirs(safe_classes_folder)

    analyzed_jars = set()

    # Let's peek into every folder with jars to see if we have classes in scope!
    for folder_with_jars in folders_with_jars:
        # For every jar file in the safe_classes_folder, we use tar tf to list the content
        # if there is a class in scope, then we consider the jar in scope.
        for jar in os.listdir(folder_with_jars):
            if jar.endswith(".jar") and jar not in analyzed_jars:
                analyzed_jars.add(jar)
                print(f'Checking {jar}')
                exit_code, stdout, stderr = run_command(f"jar tf {folder_with_jars}/{jar}")

                if exit_code == -1:
                    print(f' 🤡 Fatal error during jar tf {jar}. Skipping')
                    return False
                elif exit_code != 0:
                    print(f' 🤡 Non-Fatal error during jar tf {jar}')
                    print(f"{exit_code=}\n{stdout=}{stderr=}")
                    
                # data is whatever is not empty
                data = stdout if stdout else stderr
                for line in data.splitlines():
                    if ".class" in line:
                        # This is class, is it in scope?
                        class_name = line.replace(".class", '')
                        
                        if class_name in classes_in_scope:
                            print(f'✅ {jar} is in scope')
                            jar_in_scope[harness_name].add(jar)
                            os.system(f"cp {folder_with_jars}/{jar} {safe_classes_folder}")
                            os.system(f"cd {safe_classes_folder} && jar xf {jar}")
                            break
            else:
                continue
    
    # After we processed all the jars in the folder, we check if we have any classes in scope
    if len(jar_in_scope[harness_name]) == 0:
        print(f'💀 No jars in scope for {harness_name}. This is pretty cursed.')
        # This error is cursed. I don't know how to recover.
        # 🧨 Consequences: 
        #    -> No classes in scope for coverage 
        #    -> Collection of coverage is down --> QuickSeed doesn't work --> InvGuy doesn't work
        assert(False)

    # For every harness, print the jars in scope
    for harness_name, jar_in_scope in jar_in_scope.items():
        print(f'There are {len(jar_in_scope)} jars in scope for {harness_name}')
        for jar in jar_in_scope:
            print(f'   - 📦 {jar}')

    #print(f" Showing content of that folder: ")
    # check the number of classes in SAFE_CLASSES_AT
    #os.system(f'cd {safe_classes_folder} && ls -lh')
    

if __name__ == "__main__":
    main()
