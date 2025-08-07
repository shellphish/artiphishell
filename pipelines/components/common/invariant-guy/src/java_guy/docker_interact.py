


import subprocess
import os

from .jutils import *

'''

These APIs are used to interact with the CP docker container 
that uses.


        {docker_interact.py} |--> run.sh 
    |___________________________|   =>  |________________________________|
             invguy-docker                           cp-docker
|________________________________________________________________________|
                                   host

'''

DISABLE_ASLR = "echo 0 | tee /proc/sys/kernel/randomize_va_space"

def run_sync_command(out_folder, cmd):
    try:        
        # NOTE: do not pipe stdout and stderr:
        # see https://chatgpt.com/c/c3acaac8-55d0-40a0-b538-f053306f4813
        # TL;DR; if the pipe fills up, subprocess get stuck
        pid = subprocess.Popen(cmd, shell=True, text=False)
        pid.wait()

        # print stdout and stderr
        #stdout = pid.stdout.read().decode('utf-8')
        #stderr = pid.stderr.read().decode('utf-8')
        #print(stdout, stderr)

        # the docker command creates a folder in /out/output
        #print(f'Checking out folder {out_folder}')

        if not os.path.exists(out_folder):
            print(f'🤡🤡 No output folder at {out_folder} after running a command. Clowny (you probably forgot --privileged)')
            assert(False)

        new_dirs = os.listdir(out_folder)
        
        #print(new_dirs)
        if len(new_dirs) == 0:
            print(f'🤡 No output folder after running a command. Pretty clow business')
            assert(False)
        if len(new_dirs) > 1:
            print(f'🤡 More than one output folder after running a command in the docker. Still clown business tbh.')
            assert(False)
        
        the_output_dir = new_dirs[0]

        stdout_log = f"{out_folder}/{the_output_dir}/stdout.log"
        stderr_log = f"{out_folder}/{the_output_dir}/stderr.log"
        exit_code_log = f"{out_folder}/{the_output_dir}/exitcode"
        docker_cid = f"{out_folder}/{the_output_dir}/docker.cid"

        stdout = open(stdout_log, 'r').read()
        stderr = open(stderr_log, 'r').read()
        exit_code = open(exit_code_log, 'r').read()

        return exit_code, stdout, stderr

    except subprocess.CalledProcessError as e:
        print(e)
        return "", "", ""

def docker_run_custom_command(target_folder, docker_command):
    # This is going to run a command inside the docker container
    # using the run.sh script
    # The docker image name has already been set in the .env.project

    out_folder = f"{target_folder}/out/output"
    os.system(f'rm -rf {out_folder}/*')

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd = f'cd {target_folder} && ./run.sh custom {docker_command}'
    cmd = DISABLE_ASLR + " && " + cmd
    print(f'🐳 {cmd}')
    return run_sync_command(out_folder, cmd)


def docker_run_pov_command(target_folder, target_harness, pov_path):
    # This is going to run a pov inside the docker container
    # using the run.sh script
    # The docker image name has already been set in the .env.project

    out_folder = f"{target_folder}/out/output"
    os.system(f'rm -rf {out_folder}/*')

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd = f'cd {target_folder} && ./run.sh run_pov {pov_path} {target_harness}'
    cmd = DISABLE_ASLR + " && " + cmd
    print(f'🐳 {cmd}')
    return run_sync_command(out_folder, cmd)


def docker_run_tests(target_folder):
    # This is going to run the tests inside the docker container
    # using the run.sh script
    # The docker image name has already been set in the .env.project

    out_folder = f"{target_folder}/out/output"
    os.system(f'rm -rf {out_folder}/*')

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd = f'cd {target_folder} && ./run.sh run_tests'
    cmd = DISABLE_ASLR + " && " + cmd
    print(f'🐳 {cmd}')
    exit_code, stdout, stderr = run_sync_command(out_folder, cmd)
    print(exit_code, stdout, stderr)
    return exit_code, stdout, stderr

def docker_run_build(target_folder, patch_file=None, patch_source=None):
    # This is going to build the target inside the docker container
    # using the run.sh script
    # The docker image name has already been set in the .env.project

    out_folder = f"{target_folder}/out/output"
    os.system(f'rm -rf {out_folder}/*')

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd = f'cd {target_folder} && ./run.sh build'

    # if a patch is provided (by patcher-y), apply the patch through the run.sh build script
    if patch_file and patch_source:
        cmd += f' {patch_file} {patch_source}'
    elif patch_file or patch_source:
        print(f'🤡🤡🤡 You need to provide both patch_file and patch_source, or none of them. Clowny')
        assert(False)

    cmd = DISABLE_ASLR + " && " + cmd
    print(f'🐳 {cmd}')
    exit_code, stdout, stderr = run_sync_command(out_folder, cmd)
    print(exit_code, stdout, stderr)
    return exit_code, stdout, stderr