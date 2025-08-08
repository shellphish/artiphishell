

import argparse
import yaml
import os
import time

from c_guy import build_c
from java_guy import build_java
from kernel_guy import build_kernel

'''
.___              ________                      ___.         .__.__       .___
|   | _______  __/  _____/ __ __ ___.__.        \_ |__  __ __|__|  |    __| _/
|   |/    \  \/ /   \  ___|  |  <   |  |  ______ | __ \|  |  \  |  |   / __ |
|   |   |  \   /\    \_\  \  |  /\___  | /_____/ | \_\ \  |  /  |  |__/ /_/ |
|___|___|  /\_/  \______  /____/ / ____|         |___  /____/|__|____/\____ |
         \/             \/       \/                  \/                    \/
    [1] Entry point for the invariant-guy-build, this is building the targets
        with the required tools and modifications to make instrumentation possible.
            --> kernel: change the .config and add our stuff (perf) to the container.
            --> c: just build the target with debugging symbols, add perf to the container.
            --> java: add btrace to the container
'''
def main():
    argparser = argparse.ArgumentParser(description='invguy-build')

    # This is a yaml file containing the metadata of the target program
    argparser.add_argument('--target-metadata', type=str, help='path to the target metadata yaml', required=True)

    # target is the folder holding the source code of the target program (as given by pull_source)
    # NOTE: as for now we are building ourselves all the targets even if they do not need anything special for tracing
    # we are storing the compiled artifacts in /shared/invguy/<project_id>/<target_folder_name>
    argparser.add_argument('--target-dir', type=str, help='target program source code', required=True)

    # The id under which this challenge program is keyed
    argparser.add_argument('--project-id', type=str, help='project global id', required=True)

    argparser.add_argument('--target-built', type=str, help='target built folder', required=True)

    argparser.add_argument('--patch-file', type=str, help='patch (diff) file', required=False)
    argparser.add_argument('--patch-source', type=str, help='patch source', required=False)

    args = argparser.parse_args()

    #os.system("docker login ghcr.io -u player-c3f09220 -p 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")
    os.system("git config --global --add safe.directory '*'")


    # This is the folder passed by pydatatask
    target_dir = args.target_dir
    target_built = args.target_built

    # Just to make sure, if the last character is a /, remove it
    # this is important to extract the base_name of the folder later.
    # TODO maybe we should use the yaml file to get the folder name?
    if target_dir[-1] == '/':
        target_dir = target_dir[:-1]

    project_id = args.project_id
    target_metadata_yaml = args.target_metadata
    patch_file = args.patch_file
    patch_source = args.patch_source

    # Load the target metadata yaml file
    with open(target_metadata_yaml) as yaml_file:
        try:
            target_metadata = yaml.safe_load(yaml_file)
        except yaml.YAMLError as exc:
            raise Exception("Error parsing target metadata yaml file: " + str(exc))

    docker_img_address = target_metadata.get("docker_image", None)
    assert(docker_img_address is not None)

    # These are also in the .env.project
    if ":" in docker_img_address:
        docker_tag = docker_img_address.split(":")[0] + "-invguy" + ":" + docker_img_address.split(":")[1]
    else:
        docker_tag = docker_img_address + "-invguy"

    target_lang = target_metadata.get("language", None)
    assert(target_lang == "c" or target_lang == "java")

    is_kernel = False
    is_jenkins = False

    # Check if the target is a kernel or jenkins or java
    shellphish_metadata = target_metadata.get("shellphish")

    if shellphish_metadata:
        known_sources = shellphish_metadata.get("known_sources", {})
        is_kernel = "linux_kernel" in known_sources

    if is_kernel:
        # ahhhhh, very nice, we are building a kernel
        kernel_src_dir = target_dir + "/" + shellphish_metadata["known_sources"]["linux_kernel"][0]['relative_path']
        guest_kernel_src_dir = "/" + shellphish_metadata["known_sources"]["linux_kernel"][0]['relative_path']
        print(f'🎁🫀 Project info:\n - target: kernel\n - target_dir: {target_dir}\n - kernel_src_dir: {kernel_src_dir}\n docker_base_image: {docker_img_address}\n - docker_tag: {docker_tag}')
        build_kernel(target_dir, kernel_src_dir, guest_kernel_src_dir, docker_img_address, docker_tag=docker_tag, patch_file=patch_file, patch_source=patch_source)
        print("Done building target kernel!")
    elif target_lang == "c":
        print(f'🎁🏗️ Project info:\n - target: c\n - target_dir: {target_dir}\n - docker_tag: {docker_tag}')
        build_c(target_dir, target_metadata, docker_img_address, docker_tag=docker_tag, patch_file=patch_file, patch_source=patch_source)       
    elif target_lang == "java":
        print(f'🎁☕️ Project info:\n - target: java\n - target_dir: {target_dir}\n - docker_tag: {docker_tag}')
        build_java(target_dir, target_metadata, docker_img_address, docker_tag=docker_tag, patch_file=patch_file, patch_source=patch_source)        
        pass
    else:
        raise Exception("Unsupported target language: " + target_lang)

    if target_built:
        # Copy the built target to the folder assign by pydatatask
        print(f' 🖨️ Copying the built target from {target_dir}->{target_built}')
        os.system(f'cp -ra {target_dir}/. {target_built}')


if __name__ == "__main__":
    main()