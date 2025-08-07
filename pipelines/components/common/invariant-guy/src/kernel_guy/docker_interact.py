

import subprocess
import os



'''
These APIs are used to interact with the CP docker container 
that uses virtme to run the target linux kernel.

                                                     virt-me (kernel)
        {docker_interact.py} |--> run.sh            |________________|
    |___________________________|   =>  |________________________________|
             invguy-docker                     linux-cp-docker
|________________________________________________________________________|
                                   host

'''

DISABLE_ASLR = "echo 0 | tee /proc/sys/kernel/randomize_va_space"

def run_sync_command(out_folder, cmd, timeout=None):
    try:
        # NOTE: do not pipe stdout and stderr:
        # see https://chatgpt.com/c/c3acaac8-55d0-40a0-b538-f053306f4813
        # TL;DR; if the pipe fills up, subprocess get stuck
        is_timeout = False
        try:
            pid = subprocess.Popen(cmd, shell=True, text=False)
            pid.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f" >>> ⏰ Timeout expired for command {cmd} <<<")
            pid.kill()
            is_timeout = True

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

        if is_timeout:
            docker_cid_log = f"{out_folder}/{the_output_dir}/docker.cid"
            docker_cid = open(docker_cid_log, 'r').read()
            # kill that docker container
            os.system(f'docker kill {docker_cid}')
            return "", "", ""

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
    except Exception as e:
        print("SUBPROCESS ERROR")
        print(e)
        return "", "", ""

def docker_run_custom_command(target_folder, docker_command, timeout=None):
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
    return run_sync_command(out_folder, cmd, timeout=timeout)


def docker_run_custom_command_multiprocessing(target_folder, docker_command, timeout=None):
    # Same as docker_run_custom_command but ignore the output folders

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd = f'cd {target_folder} && ./run.sh custom {docker_command}'
    cmd = DISABLE_ASLR + " && " + cmd
    print(f'🐳 {cmd}')

    try:
        pid = subprocess.Popen(cmd, shell=True, text=False)
        pid.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f" >>> ⏰ Timeout expired for command {cmd} <<<")
        pid.kill()


def docker_run_pov_command(target_folder, target_harness, pov_path, timeout=None):
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
    return run_sync_command(out_folder, cmd, timeout=timeout)


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

def docker_run_build(target_folder, guest_kernel_src_dir, patch_file=None, patch_source=None):
    # This is going to build the target inside the docker container
    # using the run.sh script
    # The docker image name has already been set in the .env.project

    out_folder = f"{target_folder}/out/output"
    os.system(f'rm -rf {out_folder}/*')

    # 🔥 NOTE this command is executed from the invguy-container.
    # Therefore, we need to move to the target folder FIRST, and 
    # THEN we ./run.sh
    cmd =  f'cd {target_folder} && ./run.sh build'
    cmd += f" && cp {guest_kernel_src_dir}/arch/x86/boot/bzImage /tmp/bzImage"
    cmd += f" && cp {guest_kernel_src_dir}/vmlinux /tmp/vmlinux"
    cmd += f" && make clean"
    cmd += f" && cp /tmp/bzImage {guest_kernel_src_dir}/arch/x86/boot/bzImage"
    cmd += f" && cp /tmp/vmlinux {guest_kernel_src_dir}/vmlinux"

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