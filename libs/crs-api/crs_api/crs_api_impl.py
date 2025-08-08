import tempfile
import random
import traceback
import urllib.parse
import requests
import os
import logging
import subprocess
import tarfile
import yaml
import json
import time
import shutil

from pathlib import Path
from typing import List, Dict, Tuple
from uuid import UUID

from shellphish_crs_utils.models.aixcc_api import (
    Status,
    StatusState,
    StatusTasksState,
    SARIFBroadcast,
    SARIFMetadata,
    Task,
    TaskDetail,
    SourceType,
)
from shellphish_crs_utils.pydatatask.client import PDClient
from crs_telemetry.utils import get_otel_tracer, get_current_span
from crs_api.crs_api_base import CRSAPIBase
from crs_api.competition_api import CompetitionAPI


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# TASK_DIR = Path("/crs_scratch/tasks")
# TASK_DIR.mkdir(parents=True, exist_ok=True)

tracer = get_otel_tracer()

COMPETITION_API = CompetitionAPI(
    base_url=os.environ["COMPETITION_SERVER_URL"],
    username=os.environ["COMPETITION_SERVER_API_ID"],
    password=os.environ["COMPETITION_SERVER_API_KEY"]
)

STATUS_FILE = Path("/shared/status.json")

def get_num_concurrent_tasks():
    # TODO(FINALDEPLOY) set this to the number of task pools we have
    return int(os.environ.get("NUM_CONCURRENT_TASKS", "8"))

def store_file_in_azure_storage(file_path: str, container_path: str, timeout=None):
    file_path = Path(file_path)
    try:
        # Validate file exists
        if not file_path.exists():
            logger.error(f"❌ File not found: {file_path}")
            return

        # Check required environment variables
        required_env_vars = {
            "AZURE_STORAGE_CONTAINER_NAME": "container name",
            "AZURE_STORAGE_ACCOUNT_NAME": "account name",
            "AZURE_STORAGE_STS_TOKEN": "SAS token",
            "AZURE_STORAGE_CONNECTION_STRING": "connection string"
        }
        
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            logger.warning(f"⚠️ Missing required Azure storage environment variables: {', '.join(missing_vars)}")
            return

        storage_container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME")
        deployment_name = os.getenv("DEPLOYMENT_NAME", 'artiphishell')
        container_path = f'backups/{deployment_name}/{container_path}'

        cmd = [
            'az', 'storage', 'blob', 'upload',
            '--container-name', storage_container_name,
            '--account-name', os.getenv("AZURE_STORAGE_ACCOUNT_NAME"),
            '--file', str(file_path),
            '--name', container_path,
            '--sas-token', os.getenv("AZURE_STORAGE_STS_TOKEN"),
            '--connection-string', os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
            '--overwrite',
        ]

        if timeout:
            cmd = ['timeout', str(timeout), *cmd]

        # Uploads in a background process
        logger.info(f"☁️🗃️ Storing {file_path} in {storage_container_name}:{container_path}")
        upload_process = subprocess.Popen(
            cmd,
            start_new_session=True
        )
        upload_process.poll()
    except Exception as e:
        import traceback
        logger.error(f"Error storing {file_path} in {storage_container_name}:{container_path}: {e}")
        logger.error(traceback.format_exc())
        return

TASK_POOL_STATE_FILE = "/shared/task_pool_state.json"
TASK_POOL_STATE_LOCK = "/shared/task_pool_state.lock"

BONUS_BUDGET_FILE = "/shared/llm_budget_bonus.json"
BONUS_BUDGET_LOCK = "/shared/llm_budget_bonus.lock"

TASK_RECORD_FILE = "/shared/task_record.json"
TASK_RECORD_LOCK = "/shared/task_record.lock"

from filelock import FileLock, Timeout

from contextlib import contextmanager

@contextmanager
def optional_filelock(lock_path, timeout=10, max_retries=3, retry_delay=0.1):
    """
    best-effort file lock. tries to acquire, but continues anyway if it can't.
    
    useful for resource optimizations where locking is preferred but not required.
    """
    retries = 0
    lock = FileLock(lock_path, timeout=timeout)
    
    while retries < max_retries:
        try:
            with lock:
                yield True  # indicates we got the lock
                return
        except Timeout:
            retries += 1
            if retries >= max_retries:
                break
            
            # attempt to remove potentially stale lock
            try:
                os.remove(lock_path)
                time.sleep(retry_delay)
            except:
                pass
    
    # couldn't get lock, but continue anyway
    yield False  # indicates we're proceeding without lock

def record_new_tasking(task_id, task_metadata):
    with optional_filelock(TASK_RECORD_LOCK, timeout=10) as got_lock:
        if not got_lock:
            logger.warning(f"🤡 Couldn't acquire lock for {TASK_RECORD_LOCK}, proceeding anyway")

        if os.path.exists(TASK_RECORD_FILE):
            with open(TASK_RECORD_FILE, "r") as f:
                task_record = json.load(f)
        else:
            task_record = {}

        if task_id in task_record:
            logger.warning(f"🤔 Task {task_id} already in task record, skipping")
            return

        task_record[task_id] = task_metadata
        task_metadata["successfully_ingested"] = True
        logger.info(f"🤡 Recorded new task {task_id} with metadata {task_metadata}")

        with open(TASK_RECORD_FILE + ".tmp", "w") as f:
            json.dump(task_record, f)
        os.rename(TASK_RECORD_FILE + ".tmp", TASK_RECORD_FILE)

def mark_task_as_ingested(task_id: str):
    with optional_filelock(TASK_RECORD_LOCK, timeout=10) as got_lock:
        if not got_lock:
            logger.warning(f"🤡 Couldn't acquire lock for {TASK_RECORD_LOCK}, proceeding anyway")
        
        if os.path.exists(TASK_RECORD_FILE):
            with open(TASK_RECORD_FILE, "r") as f:
                task_record = json.load(f)
        else:
            task_record = {}

        if task_id not in task_record:
            logger.warning(f"🤔 Task {task_id} not in task record, skipping")
            return

        task_record[task_id]["successfully_ingested"] = True
        logger.info(f"✅ Marked task {task_id} as successfully ingested")

        with open(TASK_RECORD_FILE + ".tmp", "w") as f:
            json.dump(task_record, f)
        os.rename(TASK_RECORD_FILE + ".tmp", TASK_RECORD_FILE)

def get_task_pool_state():
    if not os.path.exists(TASK_POOL_STATE_FILE):
        return {}
    try:
        with open(TASK_POOL_STATE_FILE, "r") as f:
            return json.load(f)
    except:
        logger.error("Error loading task pool state: %s", traceback.format_exc())
        return {}

def get_task_pool_for_task_id(task_id: str) -> tuple[str|None, int|None]:
    with optional_filelock(TASK_POOL_STATE_LOCK, timeout=10) as got_lock:
        if not got_lock:
            logger.warning(f"🤡 Couldn't acquire lock for {TASK_POOL_STATE_LOCK}, proceeding anyway")

        state = get_task_pool_state()
        NUM_TASK_POOLS = get_num_concurrent_tasks()
        for i in range(NUM_TASK_POOLS):
            name = f"task{i+1}"
            if name not in state:
                continue
            obj = state[name]
            if not isinstance(obj, dict):
                logger.error("Task pool state is not a dictionary: %s", obj)
                continue
            if obj.get("task_id") == task_id:
                return name, i + 1
    return None, None

def record_tasking(task_id: str, task_metadata: dict):
    with optional_filelock(TASK_RECORD_LOCK, timeout=10) as got_lock:
        if not got_lock:
            logger.warning(f"🤡 Couldn't acquire lock for {TASK_RECORD_LOCK}, proceeding anyway")

        if os.path.exists(TASK_RECORD_FILE):
            with open(TASK_RECORD_FILE, "r") as f:
                task_record = json.load(f)
        else:
            task_record = {}
        
        task_record[task_id] = task_metadata
        with open(TASK_RECORD_FILE + ".tmp", "w") as f:
            json.dump(task_record, f)

        os.rename(TASK_RECORD_FILE + ".tmp", TASK_RECORD_FILE)

#def get_task_record(task_id: str) -> dict:

def assign_task_pool(task_id: str, deadline: int, task_type: str, **kwargs) -> tuple[str|None, int|None]:
    deadline -= 120
    with optional_filelock(TASK_POOL_STATE_LOCK, timeout=10) as got_lock:
        if not got_lock:
            logger.warning(f"🤡 Couldn't acquire lock for {TASK_POOL_STATE_LOCK}, proceeding anyway")

        state = get_task_pool_state()
        NUM_TASK_POOLS = get_num_concurrent_tasks()

        selected_name = None
        selected_num = None
        now = time.time()

        for i in range(NUM_TASK_POOLS):
            name = f"task{i+1}"
            if name not in state:
                selected_name = name
                selected_num = i + 1
                break
            obj = state[name]
            if not isinstance(obj, dict):
                logger.error("Task pool state is not a dictionary: %s", obj)
                selected_name = name
                selected_num = i + 1
                break

            if obj.get("task_id") == task_id:
                logger.info("Task %s already assigned to task pool %s with num %s", task_id, name, i + 1)
                return name, i + 1

            old_deadline = obj.get("deadline", 0)
            if old_deadline < now:
                selected_name = name
                selected_num = i + 1
                break

            # Check to make sure the agent is reachable
            client = CRSAPI.get_pd_client(i + 1)
            try:
                client.health()
            except Exception as e:
                logger.warning(f"⚠️⚠️⚠️ PD agent {i + 1} is not reachable, skipping assignment: {e}")
                continue

        if selected_name is None:
            logger.error("No task pool available, selecting one at random!!!!")
            ind = random.randint(1, NUM_TASK_POOLS)
            selected_name = f"task{ind}"
            selected_num = ind
        
        state[selected_name] = {
            "start_time": int(time.time()),
            "task_id": task_id,
            "deadline": deadline,
            "type": task_type,
            **kwargs,
        }
        logger.info(f"Assigning task {task_id} to task pool {selected_name} with num {selected_num}")
        with open(TASK_POOL_STATE_FILE + ".tmp", "w") as f:
            json.dump(state, f)
        os.rename(TASK_POOL_STATE_FILE + ".tmp", TASK_POOL_STATE_FILE)
        return selected_name, selected_num

def add_bonus_task(task_id: str, start_time: int):
    try:
        with optional_filelock(BONUS_BUDGET_LOCK, timeout=10) as got_lock:
            if not got_lock:
                logger.warning(f"🤡 Couldn't acquire lock for {BONUS_BUDGET_LOCK}, proceeding anyway")

            if os.path.exists(BONUS_BUDGET_FILE):
                with open(BONUS_BUDGET_FILE, "r") as f:
                    bonus_tasks = json.load(f)
            else:
                bonus_tasks = []

            # Check to see if we already counted it
            for task in bonus_tasks:
                if task['task_id'] == task_id:
                    return

            bonus_tasks.append({
                "task_id": task_id,
                "start_time": start_time,
            })
            with open(BONUS_BUDGET_FILE + ".tmp", "w") as f:
                json.dump(bonus_tasks, f)
            os.rename(BONUS_BUDGET_FILE + ".tmp", BONUS_BUDGET_FILE)
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.error("Error adding bonus task: %s", e)

class CRSAPI(CRSAPIBase):
    @staticmethod
    def use_dummy_data() -> bool:
        return os.getenv("API_COMPONENTS_USE_DUMMY_DATA", '1') == '1'

    @classmethod
    def get_tasks_status(cls) -> StatusTasksState:
        if not STATUS_FILE.exists():
            logger.warning("Status file not found: %s", STATUS_FILE)
            return cls._default_tasks_status()
        
        try:
            status = StatusTasksState.model_validate_json(STATUS_FILE.read_text())
        except Exception as e:
            logger.error("Error loading status file: %s", e, exc_info=True)
            status = cls._default_tasks_status()
        
        return status

    @staticmethod
    def _make_status(ready: bool, tasks_status: StatusTasksState, since=0, **details):
        return Status(
            details=details,
            ready=ready,
            since=since,
            state=StatusState(tasks=tasks_status),
            version="burnt-pizza-exhibition-1-b",
        )

    @staticmethod
    def _default_tasks_status():
        return StatusTasksState(
            canceled=0,
            errored=0,
            failed=0,
            pending=0,
            processing=0,
            succeeded=0,
            waiting=0,
        )

    @staticmethod
    def _return_status(status: Status):
        logger.info("Status: %s", status)
        span = get_current_span()
        span.add_event("crs-api.get_status", {"status": status.model_dump_json()})
        return status

    @classmethod
    @tracer.start_as_current_span("crs-api.get_status")
    def get_status(cls) -> Status:
        """
        Report the status of the CRS
        """
        # tasks = cls.get_all_tasks()
        tasks_status = cls._default_tasks_status()

        competition_reachable = cls.use_dummy_data()
        try:
            competition_reachable = COMPETITION_API.ping().status.lower() in [
                "ready",
                "ok",
            ]
        except Exception as e:
            if not cls.use_dummy_data():
                logger.error("Error pinging competition API: %s", e, exc_info=True)
                return cls._return_status(cls._make_status(
                    ready=False,
                    tasks_status=tasks_status,

                    # additional info
                    competition_reachable=str(competition_reachable),
                    error="Failed to connect to competition API",
                    exception=str(e),
                    backtrace=traceback.format_exc(),
                ))

        try:
            tasks_status = cls.pd_aggregate_status()
        except Exception as e:
            logger.error("Error connecting to PD agent: %s", e, exc_info=True)
            return cls._return_status(cls._make_status(
                ready=False,
                tasks_status=tasks_status,

                # additional info
                competition_reachable=str(competition_reachable),
                error="Failed to connect to PD agent",
                exception=str(e),
                backtrace=traceback.format_exc(),
            ))

        return cls._return_status(cls._make_status(
            ready=competition_reachable,
            tasks_status=tasks_status,

            # additional info
            competition_reachable=str(competition_reachable),
        ))

    @staticmethod
    def get_all_tasks() -> List[TaskDetail]:
        tasks = []
        # for task in TASK_DIR.glob("*"):
        #     tasks.append(TaskDetail.model_validate_json(task.read_text()))
        return tasks

    @classmethod
    @tracer.start_as_current_span("crs-api.consume_sarif_broadcast")
    def consume_sarif_broadcast(cls, sarif_broadcast: SARIFBroadcast) -> None:
        """
        Consume a submitted sarif broadcast
        """

        # Implement the logic to consume the SARIF broadcast
        for broadcast in sarif_broadcast.broadcasts:
            task_id = str(broadcast.task_id).replace("-", "")
            sarif_id = str(broadcast.sarif_id).replace("-", "")

            pool_name, task_num = get_task_pool_for_task_id(task_id)

            if pool_name is None:
                logger.error("No pool found for task %s", task_id)
                task_num = 1

            metadata = {}
            
            sarif_metadata = SARIFMetadata(
                metadata=broadcast.metadata,
                sarif_id=broadcast.sarif_id,
                task_id=broadcast.task_id,
                pdt_sarif_id=sarif_id,
                pdt_task_id=task_id,
            )

            logger.info(
                "Injecting SARIF report %s for Project ID %s",
                sarif_id,
                task_id,
            )
            cls.pd_inject(
                "pipeline_input.sarif_report",
                sarif_id,
                json.dumps(broadcast.sarif).encode(),
                task_num,
            )
            cls.pd_inject(
                "pipeline_input.sarif_metadata",
                sarif_id,
                sarif_metadata.model_dump_json().encode(),
                task_num,
            )
            logger.info("Injecting SARIF: %s", broadcast)
            os.environ["JOB_ID"] = task_id

    @staticmethod
    def get_file_path(url: str) -> str:
        """Helper to get file path, downloading URL if needed"""
        parsed = urllib.parse.urlparse(url)

        # If no scheme or 'file' scheme, treat as local file path
        if not parsed.scheme or parsed.scheme == "file":
            file_path = parsed.path
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Local file not found: {file_path}")
            return file_path

        # Otherwise download from URL
        try:
            logger.info(f"Downloading file from URL: {url}")
            response = requests.get(url, stream=True)
            response.raise_for_status()

            # Create temp file with appropriate extension if possible
            suffix = os.path.splitext(parsed.path)[1] or None
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                for chunk in response.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                return tmp.name

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to download file from {url}: {str(e)}")

    @staticmethod
    def get_pd_client(CRS_TASK_NUM: int|None=None):
        agent_url = None
        if CRS_TASK_NUM:
            agent_url = os.environ.get(f'PYDATATASK_AGENT_{CRS_TASK_NUM}_PORT', f"http://pydatatask-agent-{CRS_TASK_NUM}:8080")
            if not agent_url:
                agent_url = f"http://pydatatask-agent-{CRS_TASK_NUM}:8080"
        else:
            agent_url = os.environ.get("PYDATATASK_AGENT_PORT", "http://pydatatask-agent:8080")
        if not agent_url:
            raise ValueError("PD agent URL is not set in environment variables")
        agent_url = agent_url.replace("tcp://", "http://")
        agent_secret = os.environ.get("AGENT_SECRET")

        if not agent_url:
            raise ValueError("PD agent URL is not set in environment variables")

        return PDClient(agent_url, agent_secret)

    @staticmethod
    def pd_inject(name: str, pd_id: str, data: bytes, CRS_TASK_NUM: int):
        if os.getenv("IN_K8S", False):
            # Inject using the pdt agent
            logger.debug("INJECTING USING PDT AGENT")
            logger.debug("NAME: %s", name)
            logger.debug("PD_ID: %s", pd_id)
            #logger.debug("DATA: %s", data)
            client = CRSAPI.get_pd_client(CRS_TASK_NUM)
            task, link = name.split(".")
            res = client.post_data(task, link, pd_id, data)
            logger.debug("RES: %s", res)
        else:
            logger.debug("INJECTING USING SUBPROCESS")
            logger.debug("NAME: %s", name)
            logger.debug("PD_ID: %s", pd_id)
            #logger.debug("DATA: %s", data)
            subprocess.run(["pd", "inject", name, pd_id], input=data, check=True)

    @staticmethod
    def pd_is_ready() -> bool:
        num_concurrent_tasks = get_num_concurrent_tasks()
        for i in range(num_concurrent_tasks):
            task_num = i + 1
            client = CRSAPI.get_pd_client(task_num)
            if client.health() != "OK":
                logger.warning(f"PD agent {task_num} is not ready")
                return False
        return True
    @staticmethod
    def pd_aggregate_status() -> Dict[str, int]:
        """
        Aggregate status from all PDT agents by summing up each status property.
        Returns a tuple of (aggregated_status_dict, healthy_bool).
        healthy_bool is False if any agent failed to provide status.
        """
        num_concurrent_tasks = get_num_concurrent_tasks()
        aggregated_status = {
            "canceled": 0,
            "errored": 0,
            "failed": 0,
            "pending": 0,
            "processing": 0,
            "succeeded": 0,
            "waiting": 0
        }
        
        for i in range(num_concurrent_tasks):
            task_num = i + 1
            client = CRSAPI.get_pd_client(task_num)
            agent_status = client.status()
            
            # Sum up each status property
            for key in aggregated_status:
                if key in agent_status:
                    aggregated_status[key] += agent_status[key]
                    
                
        return aggregated_status

    @classmethod
    @tracer.start_as_current_span("crs-api.consume_tasking")
    def consume_tasking(cls, tasking: Task) -> None:
        """
        Consume a submitted tasking. Downloads files from URLs if needed and processes
        based on task type (full or delta).
        """
        logger.debug("Received Tasking: %s", tasking.model_dump_json(indent=2))

        try:
            for task in tasking.tasks:
                task_id = str(task.task_id)
                record_new_tasking(task_id, json.loads(task.model_dump_json()))
        except Exception as e:
            logger.error("Error recording tasking: %s", e, exc_info=True)

        try:
            for task in tasking.tasks:
                # Process each source in the task
                with tracer.start_as_current_span(
                    "crs-api.consume_tasking.task"
                ) as span:
                    # task_file = TASK_DIR / str(task.task_id)
                    # task_file.write_text(task.model_dump_json())
                    logger.info("Processing task: %s", task.model_dump_json())

                    sources = {}
                    for source in task.source:
                        logger.info(
                            "Processing source: %s, type: %s", source.url, source.type
                        )
                        if source.url.startswith("http://localhost"):
                            source_path = cls.get_file_path(
                                source.url.replace(
                                    "localhost",
                                    COMPETITION_API.base_url.replace(
                                        "http://", ""
                                    ).split(":")[0],
                                )
                            )
                        else:
                            source_path = cls.get_file_path(source.url)
                        sources[source.type] = {"path": source_path, "data": source}

                    # Extract project.yaml from oss-fuzz source
                    project_yaml = None
                    # Extract project.yaml and repackage tar without fuzz-tooling prefix
                    with tempfile.TemporaryDirectory() as temp_dir:
                        with tarfile.open(
                            sources[SourceType.SourceTypeFuzzTooling]["path"], "r:gz"
                        ) as tar:
                            # Get project.yaml contents
                            # Find the project.yaml file regardless of top-level directory name
                            yaml_path = None
                            for member in tar.getmembers():
                                if member.name.endswith(
                                    f"/projects/{task.project_name}/project.yaml"
                                ):
                                    yaml_path = member.name
                                    break

                            if not yaml_path:
                                raise FileNotFoundError(
                                    f"Could not find project.yaml for {task.project_name}"
                                )
                            yaml_file = tar.extractfile(yaml_path)
                            if yaml_file:
                                project_yaml = yaml.safe_load(yaml_file)

                            # Extract and repackage without fuzz-tooling prefix
                            tar.extractall(temp_dir)
                            fuzz_tooling_path = os.path.join(temp_dir, "fuzz-tooling")
                            if project_yaml:
                                with open(Path(temp_dir) / yaml_path, "w+") as f:
                                    project_yaml["shellphish_project_name"] = task.project_name
                                    f.write(yaml.dump(project_yaml))
                            else:
                                raise FileNotFoundError(
                                    f"Could not find project.yaml for {task.project_name}"
                                )


                            with tarfile.open(
                                sources[SourceType.SourceTypeFuzzTooling]["path"],
                                "w:gz",
                            ) as new_tar:
                                for root, dirs, files in os.walk(fuzz_tooling_path):
                                    for file in files:
                                        full_path = os.path.join(root, file)
                                        rel_path = os.path.relpath(
                                            full_path, fuzz_tooling_path
                                        )
                                        new_tar.add(full_path, arcname=rel_path)

                    assert project_yaml is not None

                    # Remove dashes from task ID
                    task_id = str(task.task_id).replace("-", "")

                    # Update task JSON with project name
                    task_json = task.model_dump_json()
                    task_json = json.loads(task_json)
                    task_json["pdt_task_id"] = task_id
                    task_json["task_uuid"] = str(task.task_id)
                    task_json["task_sanitizer"] = "address"
                    pool_name, task_num = assign_task_pool(
                        task_id,
                        task.deadline // 1000,
                        task.type,
                        name=task.project_name,
                    )
                    if pool_name is None or task_num is None:
                        logger.warning("No pool found for task %s, assigning to task1", task_id)
                        pool_name = 'task1'
                        task_num = 1

                    task_json["fuzzing_pool_name"] = pool_name
                    task_json["concurrent_target_num"] = task_num

                    logger.info("Extended Task JSON: %s", task_json)

                    do_inject = True

                    try:
                        if task.harnesses_included == False:
                            logger.info("🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨")
                            logger.info("UNHARNESSED TASK!!!! SKIPPING")
                            add_bonus_task(
                                str(task.task_id),
                                task.deadline // 1000,
                            )

                            if task.harnesses_included == False and not task.harnesses_included and str(task.harnesses_included) == "False":
                                do_inject = False
                    except Exception as e:
                        logger.error("Error processing task: %s", e, exc_info=True)

                    if do_inject:
                        # Perform pd injects in same order as run_local.sh
                        cls.pd_inject(
                            "pipeline_input.crs_task",
                            task_id,
                            json.dumps(task_json).encode("utf-8"),
                            task_num,
                        )

                        # Properly populate project_name

                        project_yaml["shellphish_project_name"] = task.project_name

                        cls.pd_inject(
                            "pipeline_input.project_metadata",
                            task_id,
                            yaml.dump(project_yaml).encode("utf-8"),
                            task_num,
                        )

                    try:
                        base_source_path = Path(sources[SourceType.SourceTypeRepo]["path"])
                        fuzz_tooling_path = Path(sources[SourceType.SourceTypeFuzzTooling]["path"])

                        backup_dir = Path("/shared/backup/targets/") / task_id
                        backup_dir.mkdir(parents=True, exist_ok=True)

                        logger.info("🗃️  Storing base source to %s", backup_dir / "base_source.tar.gz")
                        shutil.copyfile(base_source_path, backup_dir / "base_source.tar.gz")
                        store_file_in_azure_storage(backup_dir / "base_source.tar.gz", f"tasks/{task_id}/base_source.tar.gz")

                        logger.info("🗃️  Storing fuzz tooling to %s", backup_dir / "fuzz_tooling.tar.gz")
                        shutil.copyfile(fuzz_tooling_path, backup_dir / "fuzz_tooling.tar.gz")
                        store_file_in_azure_storage(backup_dir / "fuzz_tooling.tar.gz", f"tasks/{task_id}/fuzz_tooling.tar.gz")

                        logger.info("🗃️  Storing project metadata to %s", backup_dir / "project_metadata.yaml")
                        with open(backup_dir / "project_metadata.yaml", "w") as f:
                            f.write(yaml.dump(project_yaml))
                        store_file_in_azure_storage(backup_dir / "project_metadata.yaml", f"tasks/{task_id}/project_metadata.yaml")

                        logger.info("🗃️  Storing task metadata to %s", backup_dir / "task_metadata.yaml")
                        with open(backup_dir / "task_metadata.yaml", "w") as f:
                            f.write(yaml.dump(task_json))
                        store_file_in_azure_storage(backup_dir / "task_metadata.yaml", f"tasks/{task_id}/task_metadata.yaml")

                    except Exception as e:
                        logger.error("Error backing up target: %s", e, exc_info=True)

                    with open(sources[SourceType.SourceTypeRepo]["path"], "rb") as f:
                        cls.pd_inject(
                            "pipeline_input.project_base_source", task_id, f.read(),
                            task_num,
                        )
                        logger.info(
                            "Successfully injected project_base_source %s",
                            sources[SourceType.SourceTypeRepo]["path"],
                        )

                    with open(
                        sources[SourceType.SourceTypeFuzzTooling]["path"], "rb"
                    ) as f:
                        cls.pd_inject("pipeline_input.oss_fuzz_repo", task_id, f.read(), task_num)
                        logger.info(
                            "Successfully injected oss_fuzz_repo %s",
                            sources[SourceType.SourceTypeFuzzTooling]["path"],
                        )

                    if SourceType.SourceTypeDiff in sources:
                        try:
                            backup_dir = Path("/shared/backup/targets/") / task_id
                            backup_dir.mkdir(parents=True, exist_ok=True)

                            logger.info("Backing up diff to %s", backup_dir / "diff.tar.gz")
                            shutil.copyfile(sources[SourceType.SourceTypeDiff]["path"], backup_dir / "diff.tar.gz")
                            store_file_in_azure_storage(backup_dir / "diff.tar.gz", f"tasks/{task_id}/diff.tar.gz")

                        except Exception as e:
                            logger.error("Error backing up target: %s", e, exc_info=True)

                        # Extract diff file from tar
                        with tempfile.TemporaryDirectory() as temp_dir:
                            with tarfile.open(
                                sources[SourceType.SourceTypeDiff]["path"], "r:gz"
                            ) as tar:
                                tar.extractall(temp_dir)

                                diff_file = next(
                                    d for d in Path(temp_dir).rglob("*") if d.is_file()
                                )
                                with open(diff_file, "rb") as f:
                                    cls.pd_inject(
                                        "pipeline_input.project_diff", task_id, f.read(),
                                        task_num,
                                    )
                                    logger.info(
                                        "Successfully injected diff %s",
                                        sources[SourceType.SourceTypeDiff]["path"],
                                    )

                    logger.info(f"Successfully injected task {task_id}")
                    try:
                        mark_task_as_ingested(task_id)
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                        logger.error("Error marking task as ingested: %s", e)

                    os.environ["JOB_ID"] = task_id
                    span.add_event(
                        "crs-api.consume_tasking.task",
                        {
                            "task": task.model_dump_json(),
                            "pdt_task_id": task_id,
                        },
                    )

        except Exception as e:
            logger.error(
                f"Error consuming task: {str(e)}", exc_info=True, stack_info=True
            )

    @classmethod
    @tracer.start_as_current_span("crs-api.cancel_task")
    def cancel_task(cls, task_id: UUID) -> None:
        """
        Cancel a running task by uuid
        """

        # Implement the logic to cancel the task by UUID
        pdt_task_id = str(task_id).replace("-", "")

        pool_name, task_num = get_task_pool_for_task_id(pdt_task_id)
        if pool_name is None:
            logger.error("No pool found for task %s", task_id)
            task_num = 1

        cls.pd_inject("pipeline_input.project_cancel", pdt_task_id, b"cancel: true", task_num)


def sanity_check_azure_storage():
    v = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
    if not v:
        logger.warning("⚠️  No Azure storage account found, skipping using managed azure storage")
        return
    if v == 'artiphishellci':
        if not CRSAPI.use_dummy_data():
            logger.warning("🚨🚨🚨🚨🚨 YOU ARE USING DEVELOPMENT SECRETS IN A PRODUCTION DEPLOYMENT!!!!! RECTIFY THIS ASAP!!!! 🚨🚨🚨🚨🚨🚨🚨")
        else:
            logger.warning("⚠️🛠️ This is a development deployment!")
    # TODO(FINALDEPLOY) make sure this is correct
    elif v == 'artiphishellprodafc':
        logger.warning("🏆  This is a competition deployment!")


sanity_check_azure_storage()


