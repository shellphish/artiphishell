

import subprocess
import requests
import os 
import time
import shutil 
import tempfile

from argparse import ArgumentParser

from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver

FUNC_RESOLVER_URL = os.getenv("FUNC_RESOLVER_URL", None)

if FUNC_RESOLVER_URL is None:
    # set the default value to the env variable 
   os.environ['FUNC_RESOLVER_URL'] = "http://localhost:4033"
   FUNC_RESOLVER_URL = "http://localhost:4033"

print("FUNC_RESOLVER_URL: ", FUNC_RESOLVER_URL)


def remote_functionresolver_server_test(cp_name, project_id, functions_index_path, functions_jsons_path):
    global FUNC_RESOLVER_URL

    assert(os.path.exists(functions_index_path))
    assert(os.path.exists(functions_jsons_path))
    assert(FUNC_RESOLVER_URL)

    # The functions_index_path MUST be a file 
    assert(os.path.isfile(functions_index_path))
    # The functions_jsons_path MUST be a directory
    assert(os.path.isdir(functions_jsons_path))

    # Create a tempfile and make a copy of the args.functions_index_path into a file named as the project_id
    path_to_temp_dir_1 = tempfile.mkdtemp()
    print(f"Temporary directory created at: {path_to_temp_dir_1}")
    if not os.path.exists(path_to_temp_dir_1):
        os.makedirs(path_to_temp_dir_1)

    file_index_new_filename = project_id
    shutil.copyfile(functions_index_path, os.path.join(path_to_temp_dir_1, file_index_new_filename))

    # Get the name of the functions_index_path file 
    function_index_path_filename = file_index_new_filename
    function_index_path_dir = path_to_temp_dir_1

    # Get the name of the folder of the functions_jsons_path file
    functions_jsons_path_dir = os.path.normpath(functions_jsons_path)
    functions_jsons_path_dir = functions_jsons_path_dir + "/"

    print("Tarring the functions_index_path file...")

    subprocess.run(
        ["tar", "-cf", "functions_index.tar", function_index_path_filename],
        check=True,
        cwd=function_index_path_dir
    )

    path_to_functions_index_tar = os.path.join(function_index_path_dir, "functions_index.tar")

    print("Tarring the functions_jsons_path directory...")
    subprocess.run(
        ["tar", "-cf", "functions_jsons.tar", "." ],
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
        "cp_name": cp_name,
        "project_id": project_id,
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

    remote_func_resolver = RemoteFunctionResolver(cp_name="nginx", project_id=PROJECT_ID)
    local_func_resolver = LocalFunctionResolver(functions_index_path=functions_index_path, functions_jsons_path=functions_jsons_path)
    
    # ========================================
    # TESTING FUNCTION RESOLVER FUNCTIONALTIES
    # ========================================

    r = remote_func_resolver.get_funcname("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    r2 = local_func_resolver.get_funcname("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    assert r == r2, f"get_funcname mismatch: {r} != {r2}"
    assert len(list(r)) == len(list(r2)), f"get_funcname length mismatch: {len(list(r))} != {len(list(r2))}"

    r = remote_func_resolver.get_code("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    r2 = local_func_resolver.get_code("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    assert r == r2, f"get_code mismatch: {r} != {r2}"

    r = remote_func_resolver.get_function_code_line("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)", 297)
    r2 = local_func_resolver.get_function_code_line("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)", 297)
    assert r == r2, f"get_function_code_line mismatch: {r} != {r2}"

    r = remote_func_resolver.get_function_boundary("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    r2 = local_func_resolver.get_function_boundary("/src/nginx/src/core/ngx_palloc.c:297:1::void * ngx_pcalloc(ngx_pool_t *, int)")
    assert r == r2, f"get_function_boundary mismatch: {r} != {r2}"

    start_time = time.time()
    r = remote_func_resolver.resolve_with_leniency("ngx_pcalloc")
    r2 = local_func_resolver.resolve_with_leniency("ngx_pcalloc")
    assert type(r) == type(r2), f"resolve_with_leniency mismatch: {r} != {r2}"
    assert len(list(r)) == len(list(r2)), f"resolve_with_leniency length mismatch: {len(list(r))} != {len(list(r2))}"
    for x,y in zip(r, r2):
        assert x == y, f"resolve_with_leniency mismatch: {x} != {y}"
        assert type(x) == type(y), f"resolve_with_leniency type mismatch: {type(x)} != {type(y)}"

    rr1 = remote_func_resolver.find_by_funcname("ngx_pcalloc")
    rr2 = local_func_resolver.find_by_funcname("ngx_pcalloc")
    assert type(rr1) == type(rr2), f"find_by_funcname mismatch: {rr1} != {rr2}"
    assert len(list(rr1)) == len(list(rr2)), f"find_by_funcname length mismatch: {len(list(rr1))} != {len(list(rr2))}"
    for x,y in zip(rr1, rr2):
        assert x == y, f"find_by_funcname mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_funcname type mismatch: {type(x)} != {type(y)}"


    rrr1 = remote_func_resolver.find_by_filename("ngx_palloc.c")
    rrr2 = local_func_resolver.find_by_filename("ngx_palloc.c")
    assert type(rrr1) == type(rrr2), f"find_by_filename mismatch: {rrr1} != {rrr2}"
    assert len(list(rrr1)) == len(list(rrr2)), f"resolve_with_leniency length mismatch: {len(list(r))} != {len(list(r2))}"
    for x,y in zip(rrr1, rrr2):
        assert x == y, f"find_by_filename mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_filename type mismatch: {type(x)} != {type(y)}"

    # jimmy tests
    print("--- Jimmy tests ---")
    rrr1 = remote_func_resolver.find_by_filename("/src/nginx/src/stream/ngx_stream_upstream_hash_module.c")
    rrr2 = local_func_resolver.find_by_filename("/src/nginx/src/stream/ngx_stream_upstream_hash_module.c")
    assert type(rrr1) == type(rrr2), f"find_by_filename mismatch: {rrr1} != {rrr2}"
    assert len(list(rrr1)) == len(list(rrr2)), f"find_by_filename length mismatch: {len(list(rrr1))} != {len(list(rrr2))}"
    for x,y in zip(rrr1, rrr2):
        assert x == y, f"find_by_filename mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_filename type mismatch: {type(x)} != {type(y)}"

    rrr1=remote_func_resolver.find_by_funcname("ngx_stream_upstream_chash_cmp_points")
    rrr2=local_func_resolver.find_by_funcname("ngx_stream_upstream_chash_cmp_points")
    assert type(rrr1) == type(rrr2), f"find_by_funcname mismatch: {rrr1} != {rrr2}"
    assert len(list(rrr1)) == len(list(rrr2)), f"find_by_funcname length mismatch: {len(list(rrr1))} != {len(list(rrr2))}"
    for x,y in zip(rrr1, rrr2):
        assert x == y, f"find_by_funcname mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_funcname type mismatch: {type(x)} != {type(y)}"

    rrr1 = remote_func_resolver.find_by_filename("/src/nginx/src/core/ngx_resolver.c")
    rrr2 = local_func_resolver.find_by_filename("/src/nginx/src/core/ngx_resolver.c")
    assert type(rrr1) == type(rrr2), f"find_by_filename mismatch: {rrr1} != {rrr2}"
    assert len(list(rrr1)) == len(list(rrr2)), f"find_by_filename length mismatch: {len(list(rrr1))} != {len(list(rrr2))}"
    for x,y in zip(rrr1, rrr2):
        assert x == y, f"find_by_filename mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_filename type mismatch: {type(x)} != {type(y)}"


    rrr1=remote_func_resolver.find_by_funcname("ngx_resolver_resend")
    rrr2=local_func_resolver.find_by_funcname("ngx_resolver_resend")
    
    assert type(rrr1) == type(rrr2), f"find_by_funcname mismatch: {rrr1} != {rrr2}"
    assert len(list(rrr1)) == len(list(rrr2)), f"find_by_funcname length mismatch: {len(list(rrr1))} != {len(list(rrr2))}"
    for x,y in zip(rrr1, rrr2):
        assert x == y, f"find_by_funcname mismatch: {x} != {y}"
        assert type(x) == type(y), f"find_by_funcname type mismatch: {type(x)} != {type(y)}"

PROJECT_NAME = "nginx"
PROJECT_ID="11e6315934d24d4985ec18864ebaecba"
PROJECT_INDEX="/aixcc-backups/backup-nginx-14587202283/coverage_build_java.full_functions_indices/11e6315934d24d4985ec18864ebaecba"
PROJECT_JSONS="/aixcc-backups/backup-nginx-14587202283/patcherq.full_functions_jsons_dir/11e6315934d24d4985ec18864ebaecba"

if __name__ == "__main__":
    # Wiping the functionresolver_server_workdir
    # Check if the current directory contains the "artifacts" folder, if not we are running the
    # test in the wrong dir
    if not os.path.exists("artifacts"):
        raise Exception("You are not running the test in the right directory. Please run the test in the 'tests' directory.")

    os.system("rm -rf /app/functionresolver_server_workdir/*")
    # Start the server using subprocess 

    try:
        proc = subprocess.Popen(["python3", "../src/server.py"], cwd="../src/")

        print("Waiting for the server to start...")
        time.sleep(5)
        print("Testing server upload!")
        remote_functionresolver_server_test(
                                            PROJECT_NAME,
                                            PROJECT_ID,
                                            PROJECT_INDEX,
                                            PROJECT_JSONS
                                            )

        # kill the server when we are done 
        print(f"✅ Test passed!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"❌ Test failed...")
        print(e)
    finally:
        #print("Killing the server...")
        proc.kill()
