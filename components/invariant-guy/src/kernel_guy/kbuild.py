

import os

from .kutils import *
from .docker_interact import docker_run_build

CONFIG_PATCH_FILE = "/src/kernel_guy/data/.config.patch"
MAKEFILE_PATCH_FILE = "/src/kernel_guy/data/Makefile.patch"
RUN_PATCH_FILE = "/src/kernel_guy/data/run.sh.patch"


def patch_kernel_build(target_src, kernel_src,
                                   config_patch=CONFIG_PATCH_FILE,
                                   makefile_patch=MAKEFILE_PATCH_FILE,
                                   run_patch=RUN_PATCH_FILE):

    print(f'Patching kernel src at {kernel_src}')

    # Make sure the config patch exists and the target-src contains a .config file
    if not os.path.exists(config_patch):
        print(f"😭 Config patch file {config_patch} does not exist.")
        return False

    if not os.path.exists(makefile_patch):
        print(f"😭 Makefile patch file {makefile_patch} does not exist.")
        return False

    if not os.path.exists(f"{kernel_src}/.config"):
        print(f"😭 Config file .config does not exist in {kernel_src}/.config")
        return False
    
    kernel_src_basename = os.path.basename(kernel_src)

    # Update the .config using the merging script provided by the linux kernel repo.
    #os.system(f"cat {config_patch} >> {kernel_src}/.config")
    print(f' ⛙ Merging {kernel_src}/.config with {config_patch}')
    os.system(f"cd {kernel_src} && ./scripts/kconfig/merge_config.sh {kernel_src}/.config {config_patch}")
    #os.system(f"cd {kernel_src} && make olddefconfig")

    # Second, change the Makefile options with the one we need
    with open(makefile_patch, "r") as f:
        makefile_patch_content = f.read().splitlines()

    for l in makefile_patch_content:
        l = l.strip()
        if "#" in l or len(l) == 0:
            continue
        else:
            old_config = l.split("->")[0].strip()
            new_config = l.split("->")[1].strip()
            os.system(f"sed -i 's/{old_config}/{new_config}/g' {kernel_src}/Makefile")

    # change the .env.docker and re-export KERNEL_MAKE_CMD
    new_env_docker = ''
    with open(f'{target_src}/.env.docker', "r") as f:
        current_env = f.read().splitlines()
    for l in current_env:
        if 'KERNEL_MAKE_CMD' in l:
            new_cmd = f'make -C "${{SRC}}/{kernel_src_basename}" -j{NPROC_VAL} && make -C "${{SRC}}/{kernel_src_basename}" headers_install'
            new_env_docker += 'KERNEL_MAKE_CMD=' + new_cmd
        else:
            new_env_docker += l + '\n'
    with open(f'{target_src}/.env.docker', "w") as f:
        f.write(new_env_docker)

    print(f" 🩹 Kernel patched successfully.")

    return True


def build_kernel(target_dir, kernel_src_dir, guest_kernel_src_dir, docker_img_address, docker_tag='exemplar-cp-linux:base', patch_file=None, patch_source=None):
    # NOTE: For this target, we are gonna build our own custom kernel and use it
    # inside the vm spawned with qemu.
    # NOTE: target_dir is the folder of the challenge project
    #       kernel_src_dir is the folder of the kernel project (the one containing the .config file)

    # ⚠️ WARNING: I am assuming the .env.docker is empty by default

    my_env_docker = ''
    # Add the flags we need
    my_env_docker += f"NPROC_VAL={NPROC_VAL}\n"

    # Save the new .env.docker file
    with open(f'{target_dir}/.env.docker', 'w') as f:
        f.write(my_env_docker)
    
    os.system(f"mkdir -p {target_dir}/shellphish")

    os.system(f"sed -i '/DOCKER_IMAGE_NAME/d' {target_dir}/.env.project")
    os.system(f"echo 'DOCKER_IMAGE_NAME={docker_tag}' >> {target_dir}/.env.project")

    # Step 0: add the right options to the .config
    #         This will:
    #            1- add the right options to the .config file in the target_dir
    #            2- patch the Makefile to de-optimize the kernel (to have as much local variables as possible for tracing)
    #            3- add the Dockerfile.extension to the Dockerfile of the CP
    #
    # NOTE: it is safe to modify the kernel src file here because the run.sh build hasn't happened yet.
    safe_to_proceed = patch_kernel_build(target_dir, kernel_src_dir)

    if not safe_to_proceed:
        raise Exception("😭 Failed to patch the kernel build")

    # Step 1: build a new CP container with that inherits from DARPA's one.
    print(f'🧱 Building environment for kernel program compilation')
    os.system(f"cp /resources/linux-6.11.tar.gz {target_dir}/shellphish/")
    my_docker_extension = "/src/kernel_guy/data/Dockerfile.extension"
    cmd = f"cd {target_dir} && docker build --build-arg=BASE_IMAGE={docker_img_address} -t {docker_tag} -f {my_docker_extension} ."
    print(cmd)
    os.system(cmd)

    # Step 2: build!
    # NOTE: the building process is happening inside the container provided by Darpa (built at Step 1)
    # This step builds:
    #     - The kernel with our .config and our make headers install
    docker_run_build(target_dir, guest_kernel_src_dir, patch_file=patch_file, patch_source=patch_source)
    
    if not os.path.exists(f"{kernel_src_dir}/arch/x86/boot/bzImage"):
        raise Exception("😭 Failed to build the target kernel")

    return True