import asyncio
import csv
import json
import logging
import os
import shlex
import shutil
import tempfile
import time
import traceback
from argparse import ArgumentParser
from importlib import resources
from pathlib import Path
from uuid import uuid4

import jinja2
import uvicorn
import yaml
from fastapi import BackgroundTasks, FastAPI, File, Form, UploadFile

from .query_server.client import QueryServerClient
from .query_server.messages import QueryResultType
from .query_server.queryrunner import QueryRunner

# STORAGE = Path(tempfile.TemporaryDirectory().name)
STORAGE = Path("/shared/codeql_server")
STORAGE.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
uvicorn.config.LOGGING_CONFIG["formatters"]["access"]["fmt"] = (
    '%(asctime)s [%(levelname)s] %(client_addr)s "%(request_line)s" %(status_code)s'
)
uvicorn.config.LOGGING_CONFIG["formatters"]["access"]["datefmt"] = "%Y-%m-%d %H:%M:%S"
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


app = FastAPI()
tasks_store = {}
query_server_client = None
query_server_alive = False

ADDITIONAL_PACKS = [
    str(entry) for entry in Path("/compiled_packs").iterdir() if entry.is_dir()
]


async def maintain_query_server():
    global query_server_client, query_server_alive, tasks_store
    while True:
        try:
            if query_server_client is None:
                tasks_store = {
                    task_id: task
                    for task_id, task in tasks_store.items()
                    if not (
                        task["status"] == "processing" and task.get("type") == "query"
                    )
                }
                query_server_client = QueryServerClient(
                    codeql_path=Path("codeql"),
                    num_threads=0,
                    ram_mb=18 * 1024,
                    extra_args=["--search-path=" + ":".join(ADDITIONAL_PACKS)],
                )
            if (
                not query_server_client.server_process
                or not await query_server_client.server_process.is_alive()
            ):
                tasks_store = {
                    task_id: task
                    for task_id, task in tasks_store.items()
                    if not (
                        task["status"] == "processing" and task.get("type") == "query"
                    )
                }
                await query_server_client.start_server()
                query_server_alive = True
        except Exception:
            query_server_alive = False
            if query_server_client:
                await query_server_client.dispose()
            query_server_client = None
        await asyncio.sleep(5)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(maintain_query_server())


#######################
# /task/{task_id}
#######################
@app.get("/task/{task_id}")
async def get_task_result(task_id: str):
    return tasks_store.get(task_id, {"status": "not_found"})

########################
# /tasks
########################
@app.get("/tasks")
async def get_tasks():
    return {task_id: task for task_id, task in tasks_store.items()}

#######################
# /analyze
#######################
@app.post("/analyze")
async def analyze(task_data: dict, background_tasks: BackgroundTasks):
    task_id = str(uuid4())
    tasks_store[task_id] = {"status": "processing", "result": None, "type": "analyze"}
    background_tasks.add_task(process_analyze, task_id, task_data)
    return {"task_id": task_id}


async def process_analyze(task_id: str, task_data: dict):
    logger.warning("Analyze task is no longer supported, use /query instead")
    tasks_store[task_id] = {"status": "failed", "result": "Analyze task is no longer supported, use /query instead"}
    return
    start_time = time.time()
    logger.info(f"Processing analyze task {task_id} with task_data: {task_data}")
    try:
        _, db_bundle_path, _ = get_db(task_data["cp_name"], task_data["project_id"])
        result = await _run_analyze(
            db_bundle_path, task_data.get("queries", []), task_data.get("timeout", None)
        )
        elapsed_time = time.time() - start_time
        if elapsed_time > 1000:
            logger.warning(
                f"[SLOW] Analyze task {task_id} finished in {elapsed_time:.2f} seconds."
            )
        else:
            logger.info(
                f"Analyze task {task_id} finished in {elapsed_time:.2f} seconds."
            )
        tasks_store[task_id] = {"status": "completed", "result": result}
    except Exception as e:
        logger.warning(f"Error processing analyze task {task_id}: {e}")
        tasks_store[task_id] = {"status": "failed", "result": traceback.format_exc()}


async def _run_analyze(db_bundle_path, queries, timeout=None):
    with tempfile.TemporaryDirectory() as db_path:
        cmd = [
            "codeql",
            "database",
            "unbundle",
            "--target",
            db_path,
            "--name",
            "db",
            "--",
            db_bundle_path,
        ]
        result = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await result.wait()
        if result.returncode != 0:
            raise Exception(f"Failed to unbundle codeql database: {result.stderr}")
        cmd = [
            "codeql",
            "database",
            "analyze",
            "--format=sarif-latest",
            "--output=result.sarif",
            "--threads=-4",
            f"--ram={6 * 1024}",
        ]
        if ADDITIONAL_PACKS:
            cmd += ["--additional-packs=" + ":".join(ADDITIONAL_PACKS)]
        cmd += ["--", f"{db_path}/db"]
        cmd += queries
        result = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=db_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        if timeout and timeout > 0:
            try:
                await asyncio.wait_for(result.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                result.kill()
                raise TimeoutError(
                    f"CodeQL database analyze timed out after {timeout} seconds"
                )
        else:
            await result.wait()
        if result.returncode != 0:
            raise Exception(f"Failed to run codeql database analyze: {result.stderr}")
        with open(Path(db_path) / "result.sarif", "r") as f:
            return json.load(f)


#######################
# /query
#######################
@app.post("/query")
async def run_query(task_data: dict, background_tasks: BackgroundTasks):
    task_id = str(uuid4())
    tasks_store[task_id] = {"status": "processing", "result": None, "type": "query"}
    background_tasks.add_task(process_query, task_id, task_data)
    return {"task_id": task_id}


async def process_query(task_id: str, task_data: dict):
    start_time = time.time()
    logger.info(f"Processing query task {task_id} with task_data: {task_data}")
    try:
        # Validate input requirements

        if not task_data.get("cp_name") or not task_data.get("project_id"):
            raise ValueError("cp_name and project_id are required")

        if not bool(task_data.get("query_tmpl")) != bool(task_data.get("query")):
            raise ValueError("Exactly one of query_tmpl or query must be provided")

        if task_data.get("query_tmpl") and task_data.get("query_params", None) is None:
            raise ValueError("query_params is required when using query_tmpl")

        result_set = None
        entities = None

        if "result_set" in task_data:
            result_set = task_data["result_set"]

        if "entities" in task_data:
            entities = task_data["entities"]

        db_path, _, metadata = get_db(task_data["cp_name"], task_data["project_id"])

        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_qlpack_path = Path(temp_dir) / "qlpack"
            tmp_qlpack_path.mkdir()
            if "query" in task_data:
                query_path = tmp_qlpack_path / "query.ql"
                with resources.path(
                    "codeql_server.assets.qlpacks", f"dummy_{metadata['language']}"
                ) as dummy_qlpack_path:
                    for file in dummy_qlpack_path.iterdir():
                        if file.is_file() and file.suffix in [
                            ".yml",
                            ".yaml",
                            ".ql",
                            ".qll",
                        ]:
                            shutil.copy(file, tmp_qlpack_path / file.name)
                query_path.write_text(task_data["query"])
            elif "query_tmpl" in task_data:
                query_tmpl_dir, query_tmpl_file = task_data["query_tmpl"].rsplit("/", 1)
                assert "/" not in query_tmpl_dir, "don't do this please"
                assert query_tmpl_file.endswith(".j2") or query_tmpl_file.endswith(
                    ".ql"
                ), "only .j2 and .ql files are supported"

                with resources.path(
                    "codeql_server.assets.qlpacks", query_tmpl_dir
                ) as query_tmpl_dir_path:
                    for file in query_tmpl_dir_path.iterdir():
                        if file.is_file() and file.suffix in [
                            ".yml",
                            ".yaml",
                            ".ql",
                            ".qll",
                        ]:
                            shutil.copy(file, tmp_qlpack_path / file.name)

                    query_path = Path(tmp_qlpack_path / query_tmpl_file)
                    if query_tmpl_file.endswith(".j2"):
                        query_path = Path(tmp_qlpack_path / query_tmpl_file[:-3])
                        template_data = {
                            "enumerate": enumerate,
                            "range": range,
                            "len": len,
                            "sorted": sorted,
                            "zip": zip,
                            "json": json,
                            "yaml": yaml,
                            "shquote": shlex.quote,
                            "os": os,
                        }
                        template_data.update(task_data["query_params"])
                        query_path.write_text(
                            jinja2.Template(
                                (query_tmpl_dir_path / query_tmpl_file).read_text()
                            ).render(**template_data)
                        )
            cmd = ["codeql", "pack", "install"]
            result = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=tmp_qlpack_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await result.wait()
            if result.returncode != 0:
                raise Exception(f"Failed to install qlpack: {result.stderr}")
            result = await _run_query(
                db_path=db_path,
                query_path=query_path,
                result_set=result_set,
                entities=entities,
                task_id=task_id,
                timeout=task_data.get("timeout", None),
            )
            elapsed_time = time.time() - start_time
            if elapsed_time > 180:
                logger.warning(
                    f"[SLOW] Query task {task_id} finished in {elapsed_time:.2f} seconds."
                )
            else:
                logger.info(
                    f"Query task {task_id} finished in {elapsed_time:.2f} seconds."
                )
            tasks_store[task_id] = {"status": "completed", "result": result}
    except Exception as e:
        logger.warning(f"Error processing query task {task_id}: {e}")
        tasks_store[task_id] = {"status": "failed", "result": traceback.format_exc()}


def create_progress_callback(task_id):
    def progress_callback(step, total, message):
        logger.info(
            f"[{task_id}] [{step}/{total}] {message}"
        )
    
    return progress_callback

async def _run_query(db_path, query_path, result_set=None, entities=None, task_id=None, timeout=None):
    global query_server_client, query_server_alive
    while not query_server_alive:
        await asyncio.sleep(1)
    runner = QueryRunner(query_server_client)
    result = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        run_query_result = await runner.run_query(
            db_path=db_path,
            query_path=query_path,
            output_path=Path(temp_dir) / "output.bqrs",
            progress_callback=create_progress_callback(task_id),
            task_id=task_id,
            timeout=timeout,
        )
        assert run_query_result.result_type == QueryResultType.SUCCESS, (
            run_query_result.message
        )
        await runner.bqrs_to_csv(
            bqrs_path=Path(temp_dir) / "output.bqrs",
            output_path=Path(temp_dir) / "output.csv",
            result_set=result_set,
            entities=entities,
        )

        with open(Path(temp_dir) / "output.csv", "r") as f:
            reader = csv.DictReader((line.replace("\0", "") for line in f))
            result = [row for row in reader]

    return result


#######################
# /upload_db
#######################
@app.post("/upload_db")
async def upload_db(
    cp_name: str = Form(...),
    project_id: str = Form(...),
    language: str = Form(...),
    db_file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    task_id = str(uuid4())
    tasks_store[task_id] = {"status": "processing", "result": None, "type": "upload_db"}
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
        shutil.copyfileobj(db_file.file, f)
        background_tasks.add_task(
            process_db_upload, task_id, cp_name, project_id, language, f.name
        )
    return {"task_id": task_id}


async def process_db_upload(
    task_id: str, cp_name: str, project_id: str, language: str, db_file: str
):
    logger.info(
        f"Processing upload task {task_id} for {cp_name}/{project_id} with language {language}"
    )
    try:
        if is_db_exists(cp_name, project_id):
            raise ValueError(
                f"CodeQL DB with name ({cp_name}, {project_id}) already exists"
            )
        assert (STORAGE / cp_name).is_relative_to(STORAGE)
        assert (STORAGE / cp_name / project_id).is_relative_to(STORAGE / cp_name)
        db_path = STORAGE / cp_name / project_id
        db_path.mkdir(parents=True, exist_ok=True)
        shutil.move(db_file, db_path / "db.zip")
        cmd = [
            "codeql",
            "database",
            "unbundle",
            "--target",
            db_path,
            "--name",
            "db",
            "--",
            db_path / "db.zip",
        ]
        result = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await result.wait()
        if result.returncode != 0:
            raise Exception(f"Failed to unbundle codeql database: {result.stderr}")

        if language.lower() in ["c", "cpp", "c++"]:
            language = "c"
        elif language.lower() in ["java", "kotlin", "jvm"]:
            language = "java"
        else:
            raise ValueError(f"Unsupported language: {language}")
        (db_path / "metadata.yaml").write_text(
            yaml.dump(
                {
                    "language": language,
                }
            )
        )
        logger.info(
            f"Upload task {task_id} completed successfully for {cp_name}/{project_id}."
        )
        tasks_store[task_id] = {"status": "completed", "result": "Success"}
    except Exception as e:
        logger.warning(f"Error processing upload task {task_id}: {e}")
        tasks_store[task_id] = {"status": "failed", "result": traceback.format_exc()}


def is_db_exists(cp_name, project_id):
    assert (STORAGE / cp_name).is_relative_to(STORAGE)
    assert (STORAGE / cp_name / project_id).is_relative_to(STORAGE / cp_name)
    return (STORAGE / cp_name / project_id).exists()


def get_db(cp_name, project_id):
    assert is_db_exists(cp_name, project_id), (
        f"Database ({cp_name}, {project_id}) does not exist"
    )
    db_path = STORAGE / cp_name / project_id
    return (
        db_path / "db",
        db_path / "db.zip",
        yaml.safe_load((db_path / "metadata.yaml").read_text()),
    )


#######################
# /databases
#######################
@app.get("/databases")
async def databases():
    result = {}
    for cp_name in os.listdir(STORAGE):
        result[cp_name] = {}
        for project_id in os.listdir(STORAGE / cp_name):
            metadata = yaml.safe_load(
                (STORAGE / cp_name / project_id / "metadata.yaml").read_text()
            )
            result[cp_name][project_id] = metadata
    return result


def codeql_server_cli():
    parser = ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4000)
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)
