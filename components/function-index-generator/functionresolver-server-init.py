

import os
import requests
import subprocess
import tempfile
import shutil

from argparse import ArgumentParser

def functionresolver_server_init():
    parser = ArgumentParser()
    parser.add_argument("--cp_name", type=str, required=True)
    parser.add_argument("--project_id", type=str, required=True)
    parser.add_argument("--functions_index_path", type=str, required=True)
    parser.add_argument("--functions_jsons_path", type=str, required=True)
    args = parser.parse_args()

    FUNC_RESOLVER_URL = os.getenv("FUNC_RESOLVER_URL", "http://functionresolver:4033")
    if os.getenv('CRS_TASK_NUM'):
        FUNC_RESOLVER_URL = FUNC_RESOLVER_URL.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
    else:
        if 'TASKNUM' in FUNC_RESOLVER_URL:
            raise ValueError("Env CRS_TASK_NUM is not set but FUNC_RESOLVER_URL contains TASKNUM")

    assert(os.path.exists(args.functions_index_path))
    assert(os.path.exists(args.functions_jsons_path))
    assert(FUNC_RESOLVER_URL)

    # The functions_index_path MUST be a file 
    assert(os.path.isfile(args.functions_index_path))
    # The functions_jsons_path MUST be a directory
    assert(os.path.isdir(args.functions_jsons_path))

    # Create a tempfile and make a copy of the args.functions_index_path into a file named as the project_id
    path_to_temp_dir_1 = tempfile.mkdtemp()
    print(f"Temporary directory created at: {path_to_temp_dir_1}")
    if not os.path.exists(path_to_temp_dir_1):
        os.makedirs(path_to_temp_dir_1)

    file_index_new_filename = args.project_id
    shutil.copyfile(args.functions_index_path, os.path.join(path_to_temp_dir_1, file_index_new_filename))

    # Get the name of the functions_index_path file 
    function_index_path_filename = file_index_new_filename
    function_index_path_dir = path_to_temp_dir_1

    # Get the name of the folder of the functions_jsons_path file
    functions_jsons_path_dir = os.path.normpath(args.functions_jsons_path)
    functions_jsons_path_dir = functions_jsons_path_dir + "/"

    print("Tarring the functions_index_path file...")

    subprocess.run(
        ["tar", "-cvf", "functions_index.tar", function_index_path_filename],
        check=True,
        cwd=function_index_path_dir
    )

    path_to_functions_index_tar = os.path.join(function_index_path_dir, "functions_index.tar")

    print("Tarring the functions_jsons_path directory...")
    subprocess.run(
        ["tar", "-cvf", "functions_jsons.tar", "." ],
        check=True,
        cwd=functions_jsons_path_dir
    )

    path_to_functions_jsons_tar = os.path.join(functions_jsons_path_dir, "functions_jsons.tar")


    # Create an temporary directory to store the tar files
    path_to_temp_dir = tempfile.mkdtemp()

    print(f"Temporary directory created at: {path_to_temp_dir}")
 
    if not os.path.exists(path_to_temp_dir):
        os.makedirs(path_to_temp_dir)
    
    # Create the folders in the temporary directory
    subprocess.check_call(["mkdir", "-p", os.path.join(path_to_temp_dir, "functions_index")])
    subprocess.check_call(["mkdir", "-p", os.path.join(path_to_temp_dir, "functions_jsons")])

    # Move the previous tar files to the temporary directory
    subprocess.check_call(["mv", path_to_functions_index_tar, os.path.join(path_to_temp_dir, "functions_index/")])
    subprocess.check_call(["mv", path_to_functions_jsons_tar, os.path.join(path_to_temp_dir, "functions_jsons/")])

    # Assert that the files exit and they are not empty after we move them
    assert(os.path.exists(os.path.join(path_to_temp_dir, "functions_index/functions_index.tar")))
    assert(os.path.exists(os.path.join(path_to_temp_dir, "functions_jsons/functions_jsons.tar")))
    assert(os.path.getsize(os.path.join(path_to_temp_dir, "functions_index/functions_index.tar")) > 0)
    assert(os.path.getsize(os.path.join(path_to_temp_dir, "functions_jsons/functions_jsons.tar")) > 0)

    # Tar everything into data
    print("Tarring everything in data.tar...")
    subprocess.run(["tar", "-cvf", "data.tar", "functions_index/functions_index.tar", "functions_jsons/functions_jsons.tar"], cwd=path_to_temp_dir)
    path_to_final_tar = os.path.join(path_to_temp_dir, "data.tar")

    # Assert that the data.tar file exists and is not empty
    assert(os.path.exists(path_to_final_tar))
    assert(os.path.getsize(path_to_final_tar) > 0)

    # Now we ship everything to the server
    data = {
        "cp_name": args.cp_name,
        "project_id": args.project_id,
    }

    print("Sending the tar file to the server...")
    with open(path_to_final_tar, 'rb') as file:
        files = {'data': file}
        response = requests.post(FUNC_RESOLVER_URL + "/init_server", data=data, files=files)

    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")

    # Remove the temporary directory
    subprocess.run(["rm", "-rf", path_to_temp_dir])

    if "Server already initialized" in response.text:
        raise Exception("Failed to initialize Function Resolver Server!")
    else:
        print("Function Resolver Server Initialized Successfully!")

if __name__ == "__main__":
    functionresolver_server_init()