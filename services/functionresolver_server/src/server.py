import asyncio
import csv

import uvicorn
import shutil
import tempfile
import subprocess
import jinja2
import traceback
import shlex
import os
import json
import requests
import yaml
import time
from pathlib import Path
from uuid import uuid4

from typing import Dict, Iterator, List, Optional, Tuple, Union, Literal
from argparse import ArgumentParser
from importlib import resources
from fastapi import BackgroundTasks, FastAPI, File, UploadFile, Form, HTTPException

from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.function_resolver import LocalFunctionResolver
from shellphish_crs_utils.models.indexer import FunctionIndex, FUNCTION_INDEX_KEY

app = FastAPI()
tasks_store = {}


# This is the global instance of the FunctionResolvers objects, once per project.
# Every project is well-identified by the pair (cp_name, project_id)
FUNCTION_RESOLVERS: Dict[str, LocalFunctionResolver] = {}

WORKDIR = "/app/functionresolver_server_workdir/"

@app.get("/health")
async def health(
    cp_name: str,
    project_id: str,
):
    function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
    if function_resolver is None:
        return {"status": "error", "data": f"Server not initialized"}
    else:
        return {"status": "success", "data": f"Server initialized"}

@app.post("/init_server")
async def init_server(
    data: UploadFile,
    cp_name: str = Form(...),
    project_id: str = Form(...),
):

    # Make a copy of the functions index and jsons in the workdir
    project_key = f"{cp_name}_{project_id}"
    project_workdir = os.path.join(WORKDIR, project_key)

    print(f"Initializing server for project {project_key}...")

    if not os.path.exists(project_workdir):
        os.makedirs(project_workdir)
    else:
        # return an internal server error
        # if the project is already initialized
        return {
            "status": "error",
            "error": f"Server already initialized at {project_workdir} for project {project_key}",
        }

    # CLEANING JUST IN CASE...
    # If the folders already exist, wipe!
    if os.path.exists(os.path.join(project_workdir, "functions_index")):
        shutil.rmtree(os.path.join(project_workdir, "functions_index"))
    if os.path.exists(os.path.join(project_workdir, "functions_jsons")):
        shutil.rmtree(os.path.join(project_workdir, "functions_jsons"))

    # Stream the file to disk instead of loading it all into memory
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Process the file in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        while chunk := await data.read(chunk_size):
            tmp.write(chunk)
        tmp_path = tmp.name

    # Assert the tarball exists, its size its greater than 0 and it is a valid tarball
    if not os.path.exists(tmp_path):
        assert(False), "Tarball does not exist"
    if os.path.getsize(tmp_path) == 0:
        assert(False), "Tarball is empty"

    # Extract the tarball
    # Move the tarball to the workdir
    shutil.move(tmp_path, project_workdir)
    tmp_path = os.path.join(project_workdir, os.path.basename(tmp_path))

    # Extract the tarball
    subprocess.run(shlex.split(f"tar -xf {tmp_path}"), check=True, cwd=project_workdir)

    # Assert the tarball was extracted and we have the functions_index.tar and functions_jsons.tar

    # Expected result:
    # project_workdir
    #   ├── data.tar
    #   ├── functions_index
    #   |       ├── functions_index.tar
    #   └── functions_jsons
    #           ├── functions_jsons.tar

    # They MUST exist and be not empty
    if not os.path.exists(os.path.join(project_workdir, "functions_index", "functions_index.tar")):
        assert(False), "Tarball does not contain functions_index.tar"
    if not os.path.exists(os.path.join(project_workdir, "functions_jsons", "functions_jsons.tar")):
        assert(False), "Tarball does not contain functions_jsons.tar"
    if os.path.getsize(os.path.join(project_workdir, "functions_index", "functions_index.tar")) == 0:
        assert(False), "Tarball does not contain functions_index.tar"
    if os.path.getsize(os.path.join(project_workdir, "functions_jsons",  "functions_jsons.tar")) == 0:
        assert(False), "Tarball does not contain functions_jsons.tar"

    # Remove the original tarball
    subprocess.run(shlex.split(f"rm {tmp_path}"), check=True, cwd=project_workdir)

    # Extract the function index
    # (This folder is embedded in the tar we are uploading)
    # e.g., function_index_folder = "/app/functionresolver_server_workdir/nginx_1/functions_index"
    function_index_folder = os.path.join(project_workdir, "functions_index")
    subprocess.run(shlex.split(f"tar -xf functions_index.tar"), check=True, cwd=function_index_folder)

    # Expected result:
    # project_workdir
    #   ├── data.tar
    #   ├── functions_index
    #   |       ├── functions_index.tar
    #   |       └── <project_id>.yaml
    #   └── functions_jsons
    #           ├── functions_jsons.tar
    #print("[Checkpoint-debug-1] Listing the contents of the WORKDIR ...")
    #subprocess.check_call(shlex.split(f"ls -lR {project_workdir}"))

    # Assert that a file with the same name of the project_id exists
    if not os.path.exists(os.path.join(function_index_folder, project_id)):
        assert(False), f"Tarball does not contain the project_id file {os.path.join(function_index_folder, project_id)}"
    if os.path.getsize(os.path.join(function_index_folder, project_id)) == 0:
        assert(False), "Tarball does not contain the project_id file"

    # Remove the .tar
    subprocess.run(shlex.split(f"rm functions_index.tar"), check=True, cwd=function_index_folder)

    # Extract the functions jsons
    # (This folder is embedded in the tar we are uploading)
    functions_jsons_folder = os.path.join(project_workdir, "functions_jsons")
    subprocess.run(shlex.split(f"tar -xf functions_jsons.tar"), check=True, cwd=functions_jsons_folder)

    # Assert that a folder with the same name of the project_id exists
    if not os.path.exists(os.path.join(functions_jsons_folder, "FUNCTION")):
        assert(False), f"Tarball does not contain the FUNCTION folder at {os.path.join(functions_jsons_folder, 'FUNCTION')}: {os.listdir(functions_jsons_folder)}"
    # Assert that is a dir
    if not os.path.isdir(os.path.join(functions_jsons_folder, "FUNCTION")):
        assert(False), f"Tarball does not contain the FUNCTION folder at {os.path.join(functions_jsons_folder, 'FUNCTION')}: {os.listdir(functions_jsons_folder)}"

    #print("[Checkpoint-debug-2] Listing the contents of the WORKDIR ...")
    #subprocess.check_call(shlex.split(f"ls -lR {project_workdir}"))

    # Remove the .tar
    subprocess.run(shlex.split(f"rm functions_jsons.tar"), check=True, cwd=functions_jsons_folder)

   #print(f"Setup complete, listing the contents of the WORKDIR ...")
   # subprocess.check_call(shlex.split(f"ls -lR {WORKDIR}"))

    function_index_full_path = os.path.join(function_index_folder, project_id)

    print("Initializing FunctionResolver...")
    print(f"  - Function index at {function_index_full_path}")
    print(f"  - Function jsons at {functions_jsons_folder}")
    FUNCTION_RESOLVER = LocalFunctionResolver(
        functions_index_path=function_index_full_path,
        functions_jsons_path=functions_jsons_folder
    )

    print("Testing function resolver...")
    try:
        _ = list(FUNCTION_RESOLVER.find_by_funcname("LLVMFuzzerTestOneInput"))
    except Exception as e:
        print("Error while testing function resolver:")
        print(e)
        traceback.print_exc()
        assert(False), "❌ FunctionResolver is not working properly"

    print(" - [SUCCESS] FunctionResolver is working properly!")

    FUNCTION_RESOLVERS[project_key] = FUNCTION_RESOLVER

    print(f"Initialized server for project {project_key}\n - Function index at {function_index_full_path}\n - Functon jsons at {functions_jsons_folder}\n")

    print("\n")

    return {"status": "success"}

@app.post('/keys')
def keys(
    cp_name: str = Form(...),
    project_id: str = Form(...)
) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.keys()
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting keys: {e}', 'traceback': traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/get")
def get(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY=Form(...)
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.get(key)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting key {key}: {e}'}

    return {"status": "success", "data": result}

@app.post("/get_many")
def get_many(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    keys: List[FUNCTION_INDEX_KEY] = Form(...)
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.get_many(keys)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting keys {keys}: {e}'}

    return {"status": "success", "data": result}

@app.post("/get_filtered")
def get_filtered(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key_only_filter_expression: str = Form(...),
    full_filter_expression: str = Form(...),
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.get_filtered(key_only_filter_expression, full_filter_expression)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Application exception
        return {"status": "error", "data": f'Error while getting filtered keys {key_only_filter_expression=} {full_filter_expression=}: {e}'}
    return {"status": "success", "data": result}

@app.post("/find_matching_indices")
def find_matching_indices(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    indices: List[str] = Form(...),
    scope: Literal['all', 'focus', 'non-focus', 'compiled'] = Form(...),
    can_include_self: bool = Form(...)
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        matching,missing = function_resolver.find_matching_indices(indices, scope, can_include_self)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Application exception
        return {"status": "error", "data": f'Error while finding matching indices on {len(indices)} strings: {e}'}
    return {"status": "success", "matching": matching, "missing": missing}

@app.post("/find_functions_with_annotation")
def find_functions_with_annotation(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    annotation: str = Form(...),
) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.find_functions_with_annotation(annotation)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Application exception
        return {"status": "error", "data": f'Error while finding functions with annotation {annotation}: {e}'}
    return {"status": "success", "data": result}

@app.post("/get_filtered_keys")
def get_filtered_keys(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key_only_filter_expression: str = Form(...),
    full_filter_expression: str = Form(...),
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.get_filtered_keys(key_only_filter_expression, full_filter_expression)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Application exception
        return {"status": "error", "data": f'Error while getting filtered keys {key_only_filter_expression=} {full_filter_expression=}: {e}'}
    return {"status": "success", "data": result}

@app.post("/get_focus_repo_keys")
def get_focus_repo_keys(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    focus_repo_container_path: str = Form(...),
    ):
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result = function_resolver.get_focus_repo_keys(focus_repo_container_path)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting focus repo keys {focus_repo_container_path}: {e}'}
    return {"status": "success", "data": result}

@app.post("/get_funcname")
def get_funcname(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY=Form(...)
    ) -> dict:
    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "data": f"Server not initialized"}
        result:str = function_resolver.get_funcname(key)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting funcname with key: {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/get_focus_repo_relative_path")
def get_focus_repo_relative_path(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY=Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result: Optional[Path] = function_resolver.get_focus_repo_relative_path(key)
    except Exception as e:
        return {"status": "error", "data": f'Error while getting function resolver: {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/get_target_container_path")
def get_target_container_path(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY=Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result: Path = function_resolver.get_target_container_path(key)
    except Exception as e:
        return {"status": "error", "data": f'Error while getting target container path with key: {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}


@app.post("/get_code")
def get_code(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY=Form(...)) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result: Tuple[Optional[Path], Path, int, str] = function_resolver.get_code(key)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting code with key: {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}


@app.post("/get_function_boundary")
def get_function_boundary(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    key: FUNCTION_INDEX_KEY = Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result: Tuple[int,int] = function_resolver.get_function_boundary(key)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while getting function boundary with key: {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/find_by_funcname")
def find_by_funcname(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    s: str = Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result:list = list(function_resolver.find_by_funcname(s))
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while find_by_funcname({s}): {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/find_by_filename")
def find_by_filename(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    s: str = Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        result:list = function_resolver.find_by_filename(s)
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while find_by_filename({s}): {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": result}

@app.post("/resolve_with_leniency")
def resolve_with_leniency(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    name: str = Form(...)
    ) -> dict:

    try:
        function_resolver = FUNCTION_RESOLVERS.get(f"{cp_name}_{project_id}", None)
        if function_resolver is None:
            return {"status": "error", "message": "Server not initialized"}
        results = list(function_resolver.resolve_with_leniency(name))
    except Exception as e:
        # Application exception
        return {"status": "error", "data": f'Error while resolving with leniency({name}): {e}', "traceback": traceback.format_exc()}

    return {"status": "success", "data": results}

def functionresolver_server_cli():
    parser = ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4033)
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    functionresolver_server_cli()