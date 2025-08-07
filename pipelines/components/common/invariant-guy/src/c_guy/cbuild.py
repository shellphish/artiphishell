
import os

from .cutils import *
from .docker_interact import docker_run_build, docker_run_tests

def build_c(target_dir, target_metadata, docker_img_address, docker_tag='exemplar-cp-c:base', patch_file=None, patch_source=None):
    # NOTE: target_dir is the folder of the Dockerfile as provided 
    # by Darpa.

    # ⚠️ WARNING: I am assuming the .env.docker is empty by default

    my_env_docker = ''
    # Add the flags we need
    my_env_docker += "CP_BASE_EXTRA_CFLAGS=-g -O0\n"
    my_env_docker += "CP_BASE_EXTRA_CXXFLAGS=-g -O0\n"
    my_env_docker += "CP_HARNESS_EXTRA_CFLAGS=-g -O0\n"
    my_env_docker += "CP_HARNESS_EXTRA_CXXFLAGS=-g -O0\n"
    my_env_docker += f"NPROC_VAL={NPROC_VAL}\n"

    # Save the new .env.docker file
    with open(f'{target_dir}/.env.docker', 'w') as f:
        f.write(my_env_docker)
    
    # Add our custom image name
    os.system(f"sed -i '/DOCKER_IMAGE_NAME/d' {target_dir}/.env.project")
    os.system(f"echo 'DOCKER_IMAGE_NAME={docker_tag}' >> {target_dir}/.env.project")
    

    new_env_project = ''
    with open(f'{target_dir}/.env.project', 'r') as f:
        old_env_project = f.read()

    # If this is not there (weird) we add it
    if 'CP_DOCKER_EXTRA_ARGS' not in old_env_project:
        new_env_project += 'CP_DOCKER_EXTRA_ARGS=--privileged\n'

    # If the flag is there, we just add the --privileged flag
    for line in old_env_project.splitlines():
        if 'CP_DOCKER_EXTRA_ARGS' in line:
            line = line.replace('""', '')
            new_env_project +=  line + '--privileged\n'
        else:
            new_env_project += line + '\n'
    
    # Save the new .env.project file
    with open(f'{target_dir}/.env.project', 'w') as f:
        f.write(new_env_project)

    # We are gonna create a shellphish folder in the target folder
    # The Docker of the CP will be able to access these files!
    os.system(f"mkdir -p {target_dir}/shellphish")
    
    # Copy the libtraceevent folder
    # NOTE: this is needed to be compatible with both Ubuntu 20 and 22.
    # Ubuntu 20 doesn't have libtraceevent-dev on apt, so we need to do this manually.
    os.system(f"cp /src/c_guy/data/libtraceevent-1.8.2.tar.gz {target_dir}/shellphish/")
    
    # Copy the stuff needed for the hook of the harness
    # This is gonna be available in /shellphish inside the CP container
    os.system(f"cp /src/c_guy/data/in_docker_ctrace.py {target_dir}/shellphish/")

    # Copy the linux folder (for perf)
    os.system(f"cp -r /src/data_common/linux-6.10-rc5.tar.gz {target_dir}/shellphish/")

    # Step 3: build!
    print(f'🧱 Building environment for c program compilation')
    my_docker_extension = "/src/c_guy/data/Dockerfile.extension"
    cmd = f"cd {target_dir} && docker build --build-arg=BASE_IMAGE={docker_img_address} -t {docker_tag} -f {my_docker_extension} ."
    print(cmd)
    os.system(cmd)

    print(f'🧱 Building target program')
    exit_code, _, _ = docker_run_build(target_dir, patch_file=patch_file, patch_source=patch_source)
    print(f'Exit code: {exit_code}')
    if exit_code == "0":
        print(f'✅ Done building target program!')
    else:
        raise Exception(" 💩 Failed to build the target program")

    print(f'🧱 Testing target program')
    # Step 4: copy the built folder to the output_dir
    exit_code, _, _ = docker_run_tests(target_dir)
    print(f'Exit code: {exit_code}')
    if exit_code == "0":
        print(f'✅ Done testing target program!')
    else:
        raise Exception(" 💩 Failed to test the target program")
    

    # 🐸 NOTE: Here we can hijack all the harnesses with our scripts!
    # The harnesses always live in the CP folder, NOT in the container.
    # Cycle over all the harnesses in the target_metadata:
    target_harnesses = target_metadata['harnesses']
    
    assert(target_harnesses is not None and len(target_harnesses) > 0)
    
    print(f'Patching harnesses name...')

    for harness_id, harness_info in target_harnesses.items():

        # e.g., harness_bin_path is <PATH_TO_CP_FOLDER>/out/pov_harness
        harness_bin_path = os.path.join(target_dir, harness_info['binary'])
        harness_bin_name = harness_info['name']

        # The harness of course must exist 
        if not os.path.exists(harness_bin_path):
            raise Exception(f" 🤡 Cannot find the harness binary {harness_bin_path}. This is BAD.")

        print(f' Renaming the harness {harness_bin_name} to {harness_bin_name}_real')

        # Rename the harness
        copy_to = harness_bin_path + '_real'
        os.system(f"mv {harness_bin_path} {copy_to}")

        print(f' Putting our script there instead of the harness')
        # Copy our shit there
        os.system(f"cp /src/c_guy/data/in_docker_ctrace.sh {harness_bin_path}")

        # 🛡️
        os.system(f"chmod +x {harness_bin_path}")
        os.system(f"chmod +x {copy_to}")

    return True