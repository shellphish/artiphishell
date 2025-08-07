
import os
import re

from .jutils import *
from .docker_interact import docker_run_build, docker_run_tests


def add_java_import(java_code_path):
    import_injected = False
    with open(java_code_path, 'r') as f:
        lines = f.readlines()
        new_harness_code = ""
        for line in lines:
            new_harness_code += line
            if line.startswith('import ') and (not import_injected):
                new_harness_code += "import java.io.FileInputStream;\n"
                import_injected = True
    
    assert(import_injected)
    return new_harness_code
        

def replace_main_method(java_code, new_code):
    # Regular expression to match the main method, including potential throws clause
    main_method_pattern = re.compile(r'(public\s+static\s+void\s+main\s*\(\s*String\s*\[\s*\]\s*args\s*\)\s*(throws\s+[^\{]*\s*)?\{)(.*?)(\})', re.DOTALL)

    # Substitute the content of the main method
    new_java_code = main_method_pattern.sub(r'\1\n' + new_code + r'\n\4', java_code)

    return new_java_code

# NOTE: Remember to do git lfs install
def build_java(target_dir, target_metadata, base_docker_img_address, docker_tag='exemplar-cp-c:base', patch_file=None, patch_source=None):
    # NOTE: target_dir is the folder of the Dockerfile as provided 
    # by Darpa.

    # ⚠️ WARNING: I am assuming the .env.docker is empty by default

    my_env_docker = ''
    # Add the flags we need
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

    target_harnesses = target_metadata.get('harnesses', None)
    assert target_harnesses
    
    for harness_id, harness in target_harnesses.items():
        harness_src_path = harness["source"]
        harness_full_path = os.path.join(target_dir, harness_src_path)
        new_harness_code = add_java_import(harness_full_path)
        new_harness_code = replace_main_method(new_harness_code, BTRACE_MAIN_TEMPLATE)

        with open(harness_full_path, 'w') as f:
            f.write(new_harness_code)

    # We are gonna create a shellphish folder in the target folder
    # The Docker of the CP will be able to access these files!
    os.system(f"mkdir -p {target_dir}/shellphish")

    os.system(f"cp /src/java_guy/data/btrace-v2.2.5.tar.gz {target_dir}/shellphish/")
    os.system(f"cp /src/java_guy/data/in_docker_jtrace.sh {target_dir}/shellphish/")

    # Step 3: build!
    print(f'🧱 Building environment for Java program compilation')
    my_docker_extension = "/src/java_guy/data/Dockerfile.extension"
    cmd = f"cd {target_dir} && docker build --build-arg=BASE_IMAGE={base_docker_img_address} -t {docker_tag} -f {my_docker_extension} ."
    print(cmd)
    os.system(cmd)
    
    print(f'🧱 Building target program')
    exit_code, _, _ = docker_run_build(target_dir, patch_file=patch_file, patch_source=patch_source)
    print(f'Exit code: {exit_code}')
    if exit_code == "0":
        print(f'✅ Done building target program!')
    else:
        raise Exception(" 💩 Failed to build the target program")

    # print(f'🧱 Testing target program')
    
    # #Step 4: copy the built folder to the output_dir
    
    # exit_code, _, _ = docker_run_tests(target_dir)
    # print(f'Exit code: {exit_code}')
    # if exit_code == "0":
    #   print(f'✅ Done testing target program!')
    # else:
    #   raise Exception(" 💩 Failed to test the target program")

    return True