# backend/main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import aiofiles
import json
import subprocess
from typing import Dict, List, Set, Any, Optional, Iterable, AsyncGenerator
from datetime import datetime
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import io
import zipfile
from pathlib import Path
from pydatatask.pipeline import Pipeline
from pydatatask.task import Task
from pydatatask.repository import BlobRepository, YamlMetadataRepository, TarfileFilesystemRepository
import os
import shutil
import uuid
import secrets

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check if running in Kubernetes
IS_KUBERNETES = 'KUBERNETES_SERVICE_PORT' in os.environ

# Kubernetes imports only if needed
if IS_KUBERNETES:
    try:
        from kubernetes import client, config
        from kubernetes.client.rest import ApiException
        # Load in-cluster config when running in k8s
        config.load_incluster_config()
        k8s_v1 = client.CoreV1Api()
        logger.info("Kubernetes client initialized successfully")
    except Exception as e:
        logger.warning(f"Failed to initialize Kubernetes client: {e}")
        IS_KUBERNETES = False
        k8s_v1 = None
else:
    k8s_v1 = None

# Security configuration
security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security), password: str = None):
    if password is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password not configured",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    is_correct_username = secrets.compare_digest(credentials.username, "shellphish")
    is_correct_password = secrets.compare_digest(credentials.password, password)
    
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Data models
class NodeStatus(str, Enum):
    RUNNING = "running"
    RUNNING_FAILED = "running_failed"
    RUNNING_MIXED = "running_mixed"
    SUCCESS = "success"
    FAILED = "failed"
    MIXED = "mixed"
    PENDING = "pending"

@dataclass
class NodeStats:
    live: int = 0
    success: int = 0
    failed: int = 0
    timeout: int = 0
    oomkilled: int = 0
    pending: int = 0
    total: int = 0

@dataclass
class NodeInfo:
    id: str
    name: str
    status: NodeStatus
    stats: NodeStats
    repositories: Dict[str, int]
    last_updated: datetime
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class EdgeInfo:
    source: str
    target: str
    active: bool
    flow_rate: float = 0.0

@dataclass
class FileInfo:
    path: str
    name: str
    repo: str
    size: int
    modified: datetime
    type: str
    failure_type: Optional[str] = None  # For failed logs: "timeout", "oomkilled", "other", or None

class PipelineCache:
    """In-memory cache for pipeline state"""
    def __init__(self):
        self.nodes: Dict[str, NodeInfo] = {}
        self.edges: List[EdgeInfo] = []
        self.files: Dict[str, List[FileInfo]] = {}
        self.node_details: Dict[str, Dict[str, Any]] = {}  # Cache for node details
        self.last_update: datetime = datetime.now()
        self.update_lock = asyncio.Lock()
        self.task_name = ""
        self.task_id = ""
        
    async def update(self, nodes: List[NodeInfo], edges: List[EdgeInfo], task_name: str, task_id: str, node_details: Optional[Dict[str, Dict[str, Any]]] = None):
        async with self.update_lock:
            self.nodes = {node.id: node for node in nodes}
            self.edges = edges
            self.last_update = datetime.now()
            self.task_name = task_name
            self.task_id = task_id
            if node_details:
                self.node_details.update(node_details)
    
    def get_state(self) -> Dict[str, Any]:
        return {
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges],
            "task_name": self.task_name,
            "task_id": self.task_id,
            "last_update": self.last_update.isoformat(),
            "node_viz_ip": None  # This will be set by the API endpoint
        }
    
    def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get cached node details"""
        return self.node_details.get(node_id)

class ConnectionManager:
    """Manages WebSocket connections"""
    def __init__(self, update_interval: int = 5):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        self.update_interval = 30
        
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.connection_metadata[client_id] = {
            "connected_at": datetime.now(),
            "last_activity": datetime.now()
        }
        logger.info(f"Client {client_id} connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            del self.connection_metadata[client_id]
            logger.info(f"Client {client_id} disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(json.loads(json.dumps(message, default=str)))
                self.connection_metadata[client_id]["last_activity"] = datetime.now()
            except Exception as e:
                logger.error(f"Error sending to client {client_id}: {e}", exc_info=True)
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            try:
                logger.info(f"Sending message to client {client_id}")
                await websocket.send_json(json.loads(json.dumps(message, default=str)))
                self.connection_metadata[client_id]["last_activity"] = datetime.now()
            except Exception as e:
                logger.error(f"Error broadcasting to client {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)

class PipelineInterface:
    """Interface to the actual pipeline - replace with your implementation"""
    def __init__(self, pipeline: Pipeline): # Type hint pipeline for clarity
        self.pipeline = pipeline
        self.task_name = ""
        self.task_id = ""
        
    def _build_pod_name(self, task_name: str, job_id: str) -> str:
        """Build Kubernetes pod name from task name and job ID"""
        if not IS_KUBERNETES:
            raise ValueError("Not running in Kubernetes environment")
            
        crs_task_num = os.environ.get('CRS_TASK_NUM')
        if not crs_task_num:
            raise ValueError("CRS_TASK_NUM environment variable not set")
            
        # Convert task name: replace _ with -
        task_name_dashes = task_name.replace('_', '-')
        
        # Build pod name: artiphishell-<CRS_TASK_NUM>-<tasknamedashes>-<jobid>-0
        pod_name = f"artiphishell-{crs_task_num}-{task_name_dashes}-{job_id}-0"
        return pod_name
        
    async def get_pod_logs(self, task_name: str, job_id: str, tail_lines: int = 1000) -> str:
        """Get logs from a Kubernetes pod for a specific task and job"""
        if not IS_KUBERNETES or not k8s_v1:
            raise HTTPException(status_code=503, detail="Kubernetes not available")
            
        try:
            pod_name = self._build_pod_name(task_name, job_id)
            logger.info(f"Getting logs for pod: {pod_name} (tail_lines: {tail_lines})")
            
            # Get pod logs - if tail_lines is None, get full log
            if tail_lines is None:
                logs = k8s_v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace="default",
                    timestamps=True
                )
            else:
                logs = k8s_v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace="default",
                    tail_lines=tail_lines,
                    timestamps=True
                )
            
            return logs
            
        except ApiException as e:
            if e.status == 404:
                raise HTTPException(status_code=404, detail=f"Pod not found: {pod_name}")
            else:
                logger.error(f"Kubernetes API error: {e}")
                raise HTTPException(status_code=500, detail=f"Kubernetes API error: {e.reason}")
        except Exception as e:
            logger.error(f"Error getting pod logs: {e}")
            raise HTTPException(status_code=500, detail=f"Error getting pod logs: {str(e)}")

    def _determine_node_status(self, stats: NodeStats) -> NodeStatus:
        """Determines the node status based on its statistics."""
        if stats.live > 0:
            # Node is running, check completed tasks
            if stats.failed > 0:
                if stats.success > 0:
                    return NodeStatus.RUNNING_MIXED
                return NodeStatus.RUNNING_FAILED
            return NodeStatus.RUNNING

        # Node is not running, check completed tasks
        if stats.failed > 0:
            if stats.success > 0:
                return NodeStatus.MIXED
            return NodeStatus.FAILED

        if stats.success > 0:
            return NodeStatus.SUCCESS

        return NodeStatus.PENDING
    
    async def get_task_info(self, tasks: Iterable[Task]) -> dict[str, dict[str, dict[str, int]]]:
        """Retrieve the info about a given node from the repositories it is attached to and return it as a dict."""

        async def get_node_info(task: Task) -> dict[str, dict[str, int]]:
            info = {}
            for linkname, link in task.links.items():
                try:
                    keys = await link.repo.keys()
                    count = len(keys)
                except Exception as e:
                    # logger.error(f"Error getting keys for repo {linkname} in task {task.name}: {e}")
                    count = 0
                link_type = link.repo.__class__.__name__
                info[linkname] = {"type": link_type, "count": count}

            return info

        all_node_info = {
            task.name: result
            for task, result in zip(tasks, await asyncio.gather(*(get_node_info(task) for task in tasks)))
        }

        return all_node_info

    async def analyze_failure_types(self, task: Task) -> tuple[int, int]:
        """Analyze the done repository to count timeout and OOM killed failures."""
        timeout_count = 0
        oomkilled_count = 0
        
        logger.info(f"[FAILURE_ANALYSIS] Starting analysis for task: {task.name}")
        
        if not hasattr(task, 'links'):
            logger.info(f"[FAILURE_ANALYSIS] Task {task.name} has no links attribute")
            return timeout_count, oomkilled_count
            
        if 'done' not in task.links:
            logger.info(f"[FAILURE_ANALYSIS] Task {task.name} has no 'done' repository. Available repos: {list(task.links.keys())}")
            return timeout_count, oomkilled_count
            
        done_repo = task.links['done'].repo
        logger.info(f"[FAILURE_ANALYSIS] Task {task.name} done repo type: {type(done_repo).__name__}")
        
        try:
            # Check if the repo has info_all method for metadata repositories
            if hasattr(done_repo, 'info_all') and callable(done_repo.info_all):
                logger.info(f"[FAILURE_ANALYSIS] Task {task.name} using info_all method")
                all_info = await done_repo.info_all()
                logger.info(f"[FAILURE_ANALYSIS] Task {task.name} found {len(all_info)} items in done repo")
                
                for job_id, job_info in all_info.items():
                    logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} info type: {type(job_info)}")
                    if isinstance(job_info, dict):
                        logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} info keys: {list(job_info.keys())}")
                        logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} reason: {job_info.get('reason')}")
                        logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} exit_reason: {job_info.get('exit_reason')}")
                        
                        # Check for timeout
                        if job_info.get("reason") == "Timeout" or job_info.get("reason") == "Task Cancelled":
                            timeout_count += 1
                            logger.info(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} detected as TIMEOUT")
                        # Check for OOMKilled
                        elif job_info.get("exit_reason") == "OOMKilled":
                            oomkilled_count += 1
                            logger.info(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} detected as OOM_KILLED")
                        else:
                            logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} no special failure type detected")
                    else:
                        logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} job {job_id} info is not dict: {job_info}")
            else:
                # Fallback: iterate through keys and get individual info
                logger.info(f"[FAILURE_ANALYSIS] Task {task.name} using individual key iteration method")
                keys = await done_repo.keys()
                logger.info(f"[FAILURE_ANALYSIS] Task {task.name} found {len(keys)} keys in done repo")
                
                for key in keys:
                    try:
                        if hasattr(done_repo, 'info') and callable(done_repo.info):
                            job_info = await done_repo.info(key)
                            logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} key {key} info type: {type(job_info)}")
                            if isinstance(job_info, dict):
                                logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} key {key} info keys: {list(job_info.keys())}")
                                logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} key {key} reason: {job_info.get('reason')}")
                                logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} key {key} exit_reason: {job_info.get('exit_reason')}")
                                
                                # Check for timeout
                                if job_info.get("reason") == "Timeout":
                                    timeout_count += 1
                                    logger.info(f"[FAILURE_ANALYSIS] Task {task.name} key {key} detected as TIMEOUT")
                                # Check for OOMKilled
                                elif job_info.get("exit_reason") == "OOMKilled":
                                    oomkilled_count += 1
                                    logger.info(f"[FAILURE_ANALYSIS] Task {task.name} key {key} detected as OOM_KILLED")
                        else:
                            logger.debug(f"[FAILURE_ANALYSIS] Task {task.name} done repo has no info method")
                    except Exception as e:
                        logger.warning(f"[FAILURE_ANALYSIS] Error reading done repo info for key {key} in task {task.name}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"[FAILURE_ANALYSIS] Error analyzing failure types for task {task.name}: {e}")
            
        logger.info(f"[FAILURE_ANALYSIS] Task {task.name} final counts - timeout: {timeout_count}, oomkilled: {oomkilled_count}")
        return timeout_count, oomkilled_count

    async def get_job_failure_types(self, task: Task) -> Dict[str, str]:
        """Get failure type for each individual job in the done repository."""
        job_failure_types = {}
        
        logger.info(f"[JOB_FAILURE_ANALYSIS] Starting per-job analysis for task: {task.name}")
        
        if not hasattr(task, 'links'):
            logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} has no links attribute")
            return job_failure_types
            
        if 'done' not in task.links:
            logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} has no 'done' repository")
            return job_failure_types
            
        done_repo = task.links['done'].repo
        logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} done repo type: {type(done_repo).__name__}")
        
        try:
            # Check if the repo has info_all method for metadata repositories
            if hasattr(done_repo, 'info_all') and callable(done_repo.info_all):
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} using info_all method")
                all_info = await done_repo.info_all()
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} found {len(all_info)} items in done repo")
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} done repo keys: {list(all_info.keys())[:10]}...")
                
                for job_id, job_info in all_info.items():
                    if isinstance(job_info, dict):
                        # Check for failure types
                        if job_info.get("reason") == "Timeout":
                            job_failure_types[job_id] = "timeout"
                            logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} job {job_id} detected as TIMEOUT")
                        elif job_info.get("exit_reason") == "OOMKilled":
                            job_failure_types[job_id] = "oomkilled"
                            logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} job {job_id} detected as OOM_KILLED")
                        else:
                            # Check if this job failed (not in success repo)
                            success_repo = task.links.get('success')
                            if success_repo:
                                try:
                                    success_keys = await success_repo.repo.keys()
                                    logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} success repo keys: {list(success_keys)[:10]}...")
                                    if job_id not in success_keys:
                                        job_failure_types[job_id] = "other"
                                        logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} job {job_id} detected as OTHER failure")
                                except Exception as e:
                                    logger.warning(f"[JOB_FAILURE_ANALYSIS] Error checking success repo for job {job_id}: {e}")
                                    job_failure_types[job_id] = "other"
            else:
                # Fallback: iterate through keys and get individual info
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} using individual key iteration method")
                keys = await done_repo.keys()
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} found {len(keys)} keys in done repo")
                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} done repo keys: {list(keys)[:10]}...")
                
                for key in keys:
                    try:
                        if hasattr(done_repo, 'info') and callable(done_repo.info):
                            job_info = await done_repo.info(key)
                            if isinstance(job_info, dict):
                                # Check for failure types
                                if job_info.get("reason") == "Timeout":
                                    job_failure_types[key] = "timeout"
                                    logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} key {key} detected as TIMEOUT")
                                elif job_info.get("exit_reason") == "OOMKilled":
                                    job_failure_types[key] = "oomkilled"
                                    logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} key {key} detected as OOM_KILLED")
                                else:
                                    # Check if this job failed (not in success repo)
                                    success_repo = task.links.get('success')
                                    if success_repo:
                                        try:
                                            success_keys = await success_repo.repo.keys()
                                            logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} success repo keys (fallback): {list(success_keys)[:10]}...")
                                            if key not in success_keys:
                                                job_failure_types[key] = "other"
                                                logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} key {key} detected as OTHER failure")
                                        except Exception as e:
                                            logger.warning(f"[JOB_FAILURE_ANALYSIS] Error checking success repo for key {key}: {e}")
                                            job_failure_types[key] = "other"
                        else:
                            logger.debug(f"[JOB_FAILURE_ANALYSIS] Task {task.name} done repo has no info method")
                    except Exception as e:
                        logger.warning(f"[JOB_FAILURE_ANALYSIS] Error reading done repo info for key {key} in task {task.name}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"[JOB_FAILURE_ANALYSIS] Error analyzing job failure types for task {task.name}: {e}")
            
        logger.info(f"[JOB_FAILURE_ANALYSIS] Task {task.name} final job failure types: {job_failure_types}")
        return job_failure_types

    def _find_matching_failure_type(self, log_key: str, job_failure_types: Dict[str, str]) -> Optional[str]:
        """Try to find a matching failure type for a log file key using various matching strategies."""
        log_key_str = str(log_key)
        
        # Strategy 1: Exact match
        if log_key_str in job_failure_types:
            return job_failure_types[log_key_str]
        
        # Strategy 2: Remove extension (.log, .txt, etc.)
        stem = Path(log_key_str).stem
        if stem in job_failure_types:
            return job_failure_types[stem]
        
        # Strategy 3: Get just the filename (remove any path)
        filename = Path(log_key_str).name
        if filename in job_failure_types:
            return job_failure_types[filename]
        
        # Strategy 4: Get filename stem (remove path and extension)
        filename_stem = Path(log_key_str).stem if '/' in log_key_str else stem
        if filename_stem in job_failure_types:
            return job_failure_types[filename_stem]
        
        # Strategy 5: Try to match any key that contains the log key or vice versa
        for job_key in job_failure_types:
            if stem in job_key or job_key in stem:
                return job_failure_types[job_key]
        
        return None


    async def get_pipeline_state(self) -> Dict[str, Any]:
        """Get current pipeline state from the actual pipeline."""

        if not self.pipeline or not hasattr(self.pipeline, 'task_graph'):
            logger.warning("Pipeline not available or not a graph-like object.")
            return {"nodes": [], "edges": [], "task_name": self.task_name, "node_details": {}}
        
        if not self.task_name and self.pipeline.tasks.get("pipeline_input"):
            try:
                info = await self.pipeline.tasks["pipeline_input"].links["crs_task"].repo.info_all()
                for value in info.values():
                    self.task_name = value.get("project_name", "")
                    self.task_id = value.get("pdt_task_id", "")
                    break
            except Exception as e:
                logger.warning(f"Could not get task name from pipeline_input: {e}")

        nodes_info_list: List[NodeInfo] = []
        node_details: Dict[str, Dict[str, Any]] = {}

        all_task_info: dict[str, dict[str, dict[str, int]]] = await self.get_task_info(self.pipeline.tasks.values())

        # Get task objects for failure analysis
        task_lookup = {task.name: task for task in self.pipeline.tasks.values()}

        for task_name, task_info in all_task_info.items():

            live = task_info.get("live", {"count": 0})["count"]
            success = task_info.get("success", {"count": 0})["count"]
            done = task_info.get("done", {"count": 0})["count"]
            failed = done - success

            # Analyze failure types
            timeout_count = 0
            oomkilled_count = 0
            task_obj = task_lookup.get(task_name)
            if task_obj:
                logger.info(f"[PIPELINE_STATE] Analyzing failure types for task: {task_name}")
                timeout_count, oomkilled_count = await self.analyze_failure_types(task_obj)
                logger.info(f"[PIPELINE_STATE] Task {task_name} failure analysis results - timeout: {timeout_count}, oomkilled: {oomkilled_count}")
            else:
                logger.warning(f"[PIPELINE_STATE] Could not find task object for {task_name} in task_lookup")

            node_stats = NodeStats(
                live=live,
                success=success,
                failed=failed,
                timeout=timeout_count,
                oomkilled=oomkilled_count,
                pending=live,
                total=done + live
            )
            status = self._determine_node_status(node_stats)
            
            logger.info(f"[PIPELINE_STATE] Task {task_name} final NodeStats: live={live}, success={success}, failed={failed}, timeout={timeout_count}, oomkilled={oomkilled_count}, total={done + live}")
            
            node_info = NodeInfo(
                id=task_name,
                name=task_name,
                status=status,
                stats=node_stats,
                repositories={linkname: info["count"] for linkname, info in task_info.items()},
                last_updated=datetime.now(),
                metadata=None
            )
            nodes_info_list.append(node_info)

            # Get detailed node information
            node_details[task_name] = {
                    "id": task_name,
                    "name": task_name,
                    "status": status,
                    "stats": asdict(node_stats),
                    "repositories": task_info,
                    "last_updated": datetime.now().isoformat(),
                    "metadata": None,
                    "logs": None,
                    "metrics": {
                        "avg_processing_time": 0,
                        "throughput": 0,
                        "error_rate": 0,
                        "last_run": "N/A"
                    }
                }

        edges_info_list: List[EdgeInfo] = []

        for source_task_obj, target_task_obj in self.pipeline.task_graph.edges():
            source_name = getattr(source_task_obj, 'name', None)
            target_name = getattr(target_task_obj, 'name', None)

            if not source_name or not target_name:
                logger.warning(f"Edge with unnamed task found, skipping: {source_task_obj} -> {target_task_obj}")
                continue
            if source_name == target_name:
                continue

            source_node_info = next((n for n in nodes_info_list if n.id == source_name), None)
            is_active = source_node_info.status == NodeStatus.RUNNING if source_node_info else False
            
            edge_info = EdgeInfo(
                source=source_name,
                target=target_name,
                active=is_active,
                flow_rate=0.0
            )
            edges_info_list.append(edge_info)
        
        return {
            "nodes": nodes_info_list,
            "edges": edges_info_list,
            "task_name": self.task_name,
            "task_id": self.task_id,
            "node_details": node_details
        }
    
    async def get_node_files(self, node_id: str) -> List[FileInfo]:
        """Get list of files in node's repositories from the actual pipeline."""
        if not self.pipeline or not hasattr(self.pipeline, 'task_graph'):
            raise HTTPException(status_code=503, detail="Pipeline not available")

        task_lookup = {task.name: task for task in self.pipeline.task_graph.nodes()}
        task = task_lookup.get(node_id)

        if not task:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
        
        # Get job failure types for this task
        job_failure_types = await self.get_job_failure_types(task)
        logger.info(f"[GET_NODE_FILES] Task {node_id} job failure types: {job_failure_types}")
        logger.info(f"[GET_NODE_FILES] Task {node_id} job failure types keys: {list(job_failure_types.keys())}")
        
        files_list: List[FileInfo] = []
        if hasattr(task, 'links') and isinstance(task.links, dict):
            for linkname, link in task.links.items():
                if hasattr(link, 'repo') and hasattr(link.repo, 'keys') and callable(link.repo.keys):
                    try:
                        job_keys = await link.repo.keys()
                        if linkname == 'logs':
                            logger.info(f"[GET_NODE_FILES] Task {node_id} logs repo keys: {list(job_keys)[:10]}...")
                        for key in job_keys:
                            # Getting actual size, modified time, and type can be complex
                            # and repository-dependent. Using defaults for now.
                            if (hasattr(link.repo, 'blob') and hasattr(link.repo.blob, 'fullpath')) or (hasattr(link.repo, 'fullpath')):
                                if hasattr(link.repo, 'fullpath'):
                                    path = link.repo.fullpath(key)
                                else:
                                    path = link.repo.blob.fullpath(key)
                                if path.exists():
                                    if path.is_file():
                                        size = path.stat().st_size
                                    else:
                                        size = 0
                            elif isinstance(link.repo, TarfileFilesystemRepository):
                                path = link.repo.inner.fullpath(key)
                                size = path.stat().st_size if path.exists() else 0
                            else:
                                size = 0

                            # Determine failure type for this file
                            failure_type = None
                            if linkname == 'logs':
                                # For logs files, check if this job has a failure type
                                logger.info(f"[GET_NODE_FILES] Task {node_id} checking log file {key}")
                                failure_type = self._find_matching_failure_type(str(key), job_failure_types)
                                
                                if failure_type:
                                    logger.info(f"[GET_NODE_FILES] Task {node_id} file {key} has failure type: {failure_type}")
                                else:
                                    logger.info(f"[GET_NODE_FILES] Task {node_id} file {key} no failure type found (available keys: {list(job_failure_types.keys())[:5]}...)")

                            files_list.append(FileInfo(
                                path=str(key), # Ensure path is a string
                                name=Path(str(key)).name,
                                repo=linkname,
                                size=size, # Placeholder
                                modified=datetime.now(), # Placeholder
                                type="unknown", # Placeholder
                                failure_type=failure_type
                            ))
                    except Exception as e:
                        logger.error(f"Error listing files for repo {linkname} in task {node_id}: {e}")
                else:
                    logger.warning(f"Repo for link {linkname} in task {node_id} is not standard.")
        return files_list # This will be converted to List[Dict] by the caller if needed.
    
    async def get_file_content(self, node_id: str, repo_name: str, filepath: str, chunk_size: int = 1024*1024) -> AsyncGenerator[bytes, None]:
        """Get actual file content from the pipeline as a streaming generator."""
        if not self.pipeline or not hasattr(self.pipeline, 'task_graph'):
            raise HTTPException(status_code=503, detail="Pipeline not available")

        task_lookup = {task.name: task for task in self.pipeline.task_graph.nodes()}
        task = task_lookup.get(node_id)

        if not task:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
        
        if not hasattr(task, 'links') or not isinstance(task.links, dict) or repo_name not in task.links:
            raise HTTPException(status_code=404, detail=f"Repository {repo_name} not found in node {node_id}")

        repo_obj = task.links[repo_name].repo
        
        try:
            if hasattr(repo_obj, 'blobinfo') and callable(repo_obj.blobinfo):
                # For blob repositories, stream the content in chunks
                content = await repo_obj.blobinfo(filepath)
                if isinstance(content, bytes):
                    # If it's already bytes, yield it in chunks
                    for i in range(0, len(content), chunk_size):
                        yield content[i:i + chunk_size]
                else:
                    # If it's a file-like object, read it in chunks
                    while chunk := await content.read(chunk_size):
                        yield chunk
            elif hasattr(repo_obj, 'info') and callable(repo_obj.info): # For metadata repositories
                content_dict = await repo_obj.info(filepath)
                content_bytes = json.dumps(content_dict, indent=2, default=str).encode('utf-8')
                yield content_bytes
            elif isinstance(repo_obj, TarfileFilesystemRepository):
                path = repo_obj.inner.fullpath(filepath)
                if not path.exists():
                    raise FileNotFoundError(f"File not found: {filepath}")
                
                # For tar files, read and stream the content
                async with aiofiles.open(path, 'rb') as f:
                    while chunk := await f.read(chunk_size):
                        yield chunk
            else:
                logger.warning(f"Repository {repo_name} in {node_id} has no known method to get file content for {filepath}")
                raise HTTPException(status_code=501, detail="File content retrieval not supported for this repository type")
        except FileNotFoundError: # Specific exception if repo raises it
             logger.error(f"File not found: {filepath} in repo {repo_name}, node {node_id}")
             raise HTTPException(status_code=404, detail="File not found in repository")
        except Exception as e:
            logger.error(f"Error getting file content for {filepath} from repo {repo_name}, node {node_id}: {e}")
            raise HTTPException(status_code=500, detail="Error retrieving file content")

# Initialize components
cache = PipelineCache()
manager = ConnectionManager()
pipeline_interface = None
update_interval = 5
site_password = None  # Will be set when running the visualization
node_viz_ip = None  # Will be set if node-viz service exists

# In-memory progress tracking for backup tasks, keyed by task_id
backup_progress = {}
backup_tasks = {}  # task_id: asyncio.Task

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting pipeline visualization backend...")
    
    # Check for node-viz service IP
    await check_node_viz_service()
    
    # Start background tasks
    asyncio.create_task(pipeline_monitor())
    asyncio.create_task(connection_health_check())
    
    yield
    
    # Shutdown
    logger.info("Shutting down pipeline visualization backend...")

app = FastAPI(lifespan=lifespan, title="Pipeline Visualization API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Background Tasks
async def pipeline_monitor():
    """Monitor pipeline for changes and broadcast updates"""
    global update_interval
    if pipeline_interface is None:
        logger.warning("Pipeline interface not initialized, skipping pipeline monitor")
        return
    
    async with pipeline_interface.pipeline:
        
        while True:
            try:
                if pipeline_interface is None:
                    logger.warning("Pipeline interface not initialized, skipping pipeline monitor")
                    await asyncio.sleep(update_interval)
                    continue
                
                # Get current pipeline state
                logger.info("[PIPELINE_MONITOR] Getting pipeline state...")
                state = await pipeline_interface.get_pipeline_state()
                logger.info(f"[PIPELINE_MONITOR] Retrieved state for {len(state['nodes'])} nodes")
                
                # Update cache
                await cache.update(state["nodes"], state["edges"], state["task_name"], state["task_id"], state["node_details"])
                
                # Broadcast update to all connected clients
                await manager.broadcast({
                    "type": "pipeline_update",
                    "data": cache.get_state(),
                    "timestamp": datetime.now().isoformat()
                })
                
                await asyncio.sleep(update_interval)
                
            except Exception as e:
                logger.error(f"Error in pipeline monitor: {e}", exc_info=True)
                await asyncio.sleep(update_interval)
            finally:
                try:
                    pipeline_interface.pipeline.cache_flush(soft=True)
                except Exception as e:
                    logger.error(f"Error flushing pipeline cache: {e}", exc_info=True)

async def connection_health_check():
    """Periodically check connection health"""
    while True:
        try:
            # Send ping to all connections
            await manager.broadcast({
                "type": "ping",
                "timestamp": datetime.now().isoformat()
            })
            
            await asyncio.sleep(30)  # Ping every 30 seconds
            
        except Exception as e:
            logger.error(f"Error in health check: {e}")
            await asyncio.sleep(30)

async def check_node_viz_service():
    """Check if node-viz service exists and get its LoadBalancer IP"""
    global node_viz_ip
    
    if not IS_KUBERNETES or not k8s_v1:
        logger.info("Not running in Kubernetes, skipping node-viz service check")
        return
    
    try:
        # Try to get the node-viz service
        service = k8s_v1.read_namespaced_service(name="node-viz", namespace="default")
        
        # Check if it has a LoadBalancer ingress IP
        if service.status and service.status.load_balancer and service.status.load_balancer.ingress:
            ingress = service.status.load_balancer.ingress[0]
            if ingress.ip:
                node_viz_ip = ingress.ip
                logger.info(f"Found node-viz service with IP: {node_viz_ip}")
            else:
                logger.info("node-viz service found but no IP available yet")
        else:
            logger.info("node-viz service found but no LoadBalancer ingress")
            
    except Exception as e:
        logger.info(f"node-viz service not found or error accessing it: {e}")

async def get_kubernetes_pods():
    """Get kubectl pods information"""
    if not IS_KUBERNETES or not k8s_v1:
        raise HTTPException(status_code=503, detail="Kubernetes not available")
    
    try:
        # Get all pods in the default namespace
        pods = k8s_v1.list_namespaced_pod(namespace="default")
        
        pod_data = []
        for pod in pods.items:
            # Get node IP if available
            node_ip = "N/A"
            if pod.status.host_ip:
                node_ip = pod.status.host_ip
            
            # Get pod IP
            pod_ip = "N/A"
            if pod.status.pod_ip:
                pod_ip = pod.status.pod_ip
            
            # Get container statuses
            container_statuses = []
            if pod.status.container_statuses:
                for container in pod.status.container_statuses:
                    container_statuses.append({
                        "name": container.name,
                        "ready": container.ready,
                        "restart_count": container.restart_count,
                        "state": str(container.state)
                    })
            
            pod_data.append({
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "status": pod.status.phase or "Unknown",
                "node": pod.spec.node_name or "N/A",
                "node_ip": node_ip,
                "pod_ip": pod_ip,
                "age": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else "N/A",
                "containers": container_statuses
            })
        
        return pod_data
        
    except Exception as e:
        logger.error(f"Error getting Kubernetes pods: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting pods: {str(e)}")

# WebSocket endpoint
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    # WebSocket connections don't support HTTP Basic Auth directly
    # We'll rely on the fact that the client must have authenticated to get the page
    logger.info("Received websocket connection")
    await manager.connect(websocket, client_id)
    logger.info(f"Client {client_id} connected")
    
    try:
        # Send initial state
        await manager.send_to_client(client_id, {
            "type": "initial_state",
            "data": cache.get_state()
        })
        logger.info(f"Client {client_id} sent initial state")
        
        while True:
            # Receive and handle client messages
            data = await websocket.receive_text()
            message = json.loads(data)
            if pipeline_interface is None:
                logger.warning("Pipeline interface not initialized, skipping client message")
                continue
            
            if message["type"] == "pong":
                # Client responded to ping
                pass
                
            elif message["type"] == "request_node_details":
                node_id = message["nodeId"]
                details = cache.get_node_details(node_id)
                await manager.send_to_client(client_id, {
                    "type": "node_details",
                    "nodeId": node_id,
                    "data": details
                })
                
            elif message["type"] == "request_node_files":
                node_id = message["nodeId"]
                files = await pipeline_interface.get_node_files(node_id)
                await manager.send_to_client(client_id, {
                    "type": "node_files",
                    "nodeId": node_id,
                    "data": [asdict(f) for f in files]
                })
                
            elif message["type"] == "request_why_ready":
                node_id = message["nodeId"]
                try:
                    logger.info(f"Running pd why-ready for node {node_id}")
                    result = subprocess.run(['pd', 'why-ready', node_id], capture_output=True, text=True)
                    await manager.send_to_client(client_id, {
                        "type": "why_ready_result",
                        "nodeId": node_id,
                        "data": {
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                            "returncode": result.returncode
                        }
                    })
                except Exception as e:
                    logger.error(f"Error running pd why-ready for node {node_id}: {e}")
                    await manager.send_to_client(client_id, {
                        "type": "why_ready_error",
                        "nodeId": node_id,
                        "error": str(e)
                    })
                
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        manager.disconnect(client_id)

# REST API endpoints
@app.get("/")
async def root(credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    return FileResponse(os.path.join(static_dir, "front_end.html"))

@app.get("/restart")
async def restart(credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    os.system("/app/infra/agent/agent_viz.sh")
    return {"status": "restarting"}

@app.get("/health")
async def health_check(credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "connections": len(manager.active_connections),
        "last_pipeline_update": cache.last_update.isoformat()
    }

@app.get("/api/pipeline/state")
async def get_pipeline_state(credentials: HTTPBasicCredentials = Depends(security)):
    """Get current pipeline state"""
    username = get_current_username(credentials, site_password)
    state = cache.get_state()
    # Add node-viz IP to the state if available
    state["node_viz_ip"] = node_viz_ip
    out_dict = json.loads(json.dumps(state, default=str))
    return JSONResponse(content=out_dict)

@app.get("/api/nodes")
async def list_nodes(credentials: HTTPBasicCredentials = Depends(security)):
    """List all nodes"""
    username = get_current_username(credentials, site_password)
    out_dict = json.loads(json.dumps([asdict(node) for node in cache.nodes.values()], default=str))
    return JSONResponse(content=out_dict)

@app.get("/api/nodes/{node_id}")
async def get_node(node_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Get detailed information about a specific node"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    details = cache.get_node_details(node_id)
    if not details:
        raise HTTPException(status_code=404, detail="Node details not found in cache")
    
    return JSONResponse(content=json.loads(json.dumps(details, default=str)))

@app.get("/api/nodes/{node_id}/files")
async def list_node_files(node_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """List files available in a node's repositories"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")
    
    files = await pipeline_interface.get_node_files(node_id)
    out_dict = json.loads(json.dumps([asdict(f) for f in files], default=str))
    return JSONResponse(content=out_dict)

@app.get("/api/nodes/{node_id}/files/{repo}/{filepath:path}")
async def download_file(node_id: str, repo: str, filepath: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Download a specific file from a node's repository"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")

    try:
        filename = Path(filepath).name
        
        async def stream_file():
            async for chunk in pipeline_interface.get_file_content(node_id, repo, filepath, chunk_size=1024*1024):
                yield chunk
        
        return StreamingResponse(
            stream_file(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={node_id}_{repo}_{filename}"
            }
        )
    except Exception as e:
        logger.error(f"Error downloading file: {e}", exc_info=True)
        raise HTTPException(status_code=404, detail="File not found")

@app.post("/api/nodes/{node_id}/files/download-multiple")
async def download_multiple_files(node_id: str, file_paths: List[Dict[str, str]], credentials: HTTPBasicCredentials = Depends(security)):
    """Download multiple files as a zip archive"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")

    # Create zip file in memory
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for file_info in file_paths:
            try:
                # Create a temporary buffer for each file
                file_buffer = io.BytesIO()
                async for chunk in pipeline_interface.get_file_content(
                    node_id, file_info["repo"], file_info["path"]
                ):
                    file_buffer.write(chunk)
                
                # Write the complete file to the zip
                file_buffer.seek(0)
                zip_file.writestr(file_info["path"], file_buffer.getvalue())
                file_buffer.close()
            except Exception as e:
                logger.error(f"Error adding file to zip: {e}")
    
    zip_buffer.seek(0)
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={node_id}_files.zip"
        }
    )

@app.get("/api/stats")
async def get_stats(credentials: HTTPBasicCredentials = Depends(security)):
    """Get overall pipeline statistics"""
    username = get_current_username(credentials, site_password)
    total_nodes = len(cache.nodes)
    active_nodes = sum(1 for node in cache.nodes.values() if node.status == NodeStatus.RUNNING)
    success_nodes = sum(1 for node in cache.nodes.values() if node.status == NodeStatus.SUCCESS)
    failed_nodes = sum(1 for node in cache.nodes.values() if node.status == NodeStatus.FAILED)
    
    total_processed = sum(node.stats.total for node in cache.nodes.values())
    total_success = sum(node.stats.success for node in cache.nodes.values())
    total_failed = sum(node.stats.failed for node in cache.nodes.values())
    
    return {
        "nodes": {
            "total": total_nodes,
            "active": active_nodes,
            "success": success_nodes,
            "failed": failed_nodes
        },
        "processing": {
            "total": total_processed,
            "success": total_success,
            "failed": total_failed,
            "success_rate": total_success / total_processed if total_processed > 0 else 0
        },
        "connections": len(manager.active_connections),
        "last_update": cache.last_update.isoformat()
    }

@app.get("/api/nodes/{node_id}/why-ready")
async def get_why_ready(node_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Run pd why-ready for a specific node"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    try:
        import subprocess
        result = subprocess.run(['pd', 'why-ready', node_id], capture_output=True, text=True)
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except Exception as e:
        logger.error(f"Error running pd why-ready for node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/nodes/{node_id}/live/{job_id}/logs")
async def get_live_job_logs(node_id: str, job_id: str, full: bool = False, credentials: HTTPBasicCredentials = Depends(security)):
    """Get Kubernetes pod logs for a live job"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")
        
    if not IS_KUBERNETES:
        raise HTTPException(status_code=503, detail="Kubernetes logging not available - not running in Kubernetes environment")
    
    try:
        # Pass the full parameter to get_pod_logs
        tail_lines = None if full else 1000
        logs = await pipeline_interface.get_pod_logs(node_id, job_id, tail_lines)
        return {
            "logs": logs, 
            "full": full, 
            "timestamp": datetime.now().isoformat(),
            "tail_lines": tail_lines
        }
    except Exception as e:
        logger.error(f"Error getting logs for node {node_id}, job {job_id}: {e}")
        raise

@app.post("/api/backup/{task_id}")
async def backup_and_download(task_id: str, background_tasks: BackgroundTasks, credentials: HTTPBasicCredentials = Depends(security)):
    """Trigger backup, zip the directory, and stream the zip file to the user, keyed by task_id."""
    username = get_current_username(credentials, site_password)
    # If backup in progress or completed, return status
    if task_id in backup_progress:
        return {"status": backup_progress[task_id]["status"], "progress": backup_progress[task_id]["progress"], "task_id": task_id}

    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"/tmp/pd_backup_{task_id}_{now_str}"
    zip_path = f"{backup_dir}.zip"
    backup_progress[task_id] = {"status": "starting", "progress": 0}

    async def run_backup():
        try:
            backup_progress[task_id] = {"status": "running backup", "progress": 10}
            logger.info(f"Running pd backup for task {task_id}")
            proc = await asyncio.create_subprocess_exec(
                "pd", "backup", backup_dir, "--all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            logger.info(f"Backup process created for task {task_id} - {backup_dir}")
            backup_progress[task_id]["proc"] = proc
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                backup_progress[task_id] = {"status": "backup failed", "progress": 100, "error": stderr.decode()}
                logger.error(f"Backup failed for task {task_id}: {stderr.decode()}")
                return
            logger.info(f"Backup completed for task {task_id}")
            backup_progress[task_id] = {"status": "zipping", "progress": 60}
            logger.info(f"Zipping backup for task {task_id}")
            shutil.make_archive(backup_dir, 'zip', backup_dir)
            backup_progress[task_id] = {"status": "ready", "progress": 100, "zip_path": str(zip_path)}
            logger.info(f"Backup ready for task {task_id}")
        except asyncio.CancelledError:
            # Clean up on cancel
            backup_progress[task_id] = {"status": "cancelled", "progress": 0}
            logger.info(f"Backup cancelled for task {task_id}")
            try:
                if os.path.exists(backup_dir):
                    shutil.rmtree(backup_dir)
                if os.path.exists(zip_path):
                    os.remove(zip_path)
            except Exception:
                pass
        except Exception as e:
            backup_progress[task_id] = {"status": "error", "progress": 100, "error": str(e)}

    # Start the backup as a background asyncio task
    task = asyncio.create_task(run_backup())
    backup_tasks[task_id] = task
    return {"status": "starting", "progress": 0, "task_id": str(task_id)}

@app.get("/api/backup/progress/{task_id}")
async def get_backup_progress(task_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Get progress for a backup task."""
    username = get_current_username(credentials, site_password)
    task = backup_progress.get(task_id)
    if task:
        return {"status": task.get("status"), "progress": task.get("progress"), "task_id": str(task_id)}
    else:
        return {"status": "not found", "progress": 0, "task_id": str(task_id)}

@app.get("/api/backup/download/{task_id}")
async def download_backup_zip(task_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    logger.info(f"Downloading backup for task {task_id}")
    info = backup_progress.get(task_id)
    logger.info(f"Backup info for task {task_id}: {info}")
    if not info or info.get("status") != "ready" or "zip_path" not in info:
        raise HTTPException(status_code=404, detail="Backup not ready or not found")
    zip_path = info["zip_path"]
    if not os.path.exists(zip_path):
        raise HTTPException(status_code=404, detail="Zip file not found")
    filename = os.path.basename(zip_path)
    return FileResponse(zip_path, media_type="application/zip", filename=filename)

@app.post("/api/backup/cancel/{task_id}")
async def cancel_backup(task_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    # Cancel the running backup task if it exists
    task = backup_tasks.get(task_id)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
    # Clean up progress and files
    info = backup_progress.get(task_id)
    if info:
        zip_path = info.get("zip_path")
        backup_dir = None
        if zip_path:
            backup_dir = zip_path.replace('.zip', '')
        if backup_dir and os.path.exists(backup_dir):
            shutil.rmtree(backup_dir, ignore_errors=True)
        if zip_path and os.path.exists(zip_path):
            os.remove(zip_path)
    backup_progress[task_id] = {"status": "cancelled", "progress": 0}
    backup_tasks.pop(task_id, None)
    return {"status": "cancelled"}

@app.delete("/api/backup/{task_id}")
async def delete_backup(task_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_username(credentials, site_password)
    # Delete completed backup and clean up
    info = backup_progress.get(task_id)
    if info:
        zip_path = info.get("zip_path")
        backup_dir = None
        if zip_path:
            backup_dir = zip_path.replace('.zip', '')
        if backup_dir and os.path.exists(backup_dir):
            shutil.rmtree(backup_dir, ignore_errors=True)
        if zip_path and os.path.exists(zip_path):
            os.remove(zip_path)
    backup_progress.pop(task_id, None)
    backup_tasks.pop(task_id, None)
    return {"status": "deleted"}

@app.get("/api/kubernetes/pods")
async def get_k8s_pods(credentials: HTTPBasicCredentials = Depends(security)):
    """Get Kubernetes pods information"""
    username = get_current_username(credentials, site_password)
    try:
        pods_data = await get_kubernetes_pods()
        return JSONResponse(content=pods_data)
    except Exception as e:
        logger.error(f"Error getting Kubernetes pods: {e}")
        raise

@app.delete("/api/nodes/{node_id}/repos/done")
async def delete_done_repo(node_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Delete entire done repository for a node"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")

    try:
        # Get the task object
        task_lookup = {task.name: task for task in pipeline_interface.pipeline.task_graph.nodes()}
        task = task_lookup.get(node_id)

        if not task:
            raise HTTPException(status_code=404, detail=f"Task {node_id} not found")

        if not hasattr(task, 'links') or 'done' not in task.links:
            raise HTTPException(status_code=404, detail=f"Task {node_id} has no 'done' repository")

        done_repo = task.links['done'].repo
        
        # Get all keys and delete them
        keys = await done_repo.keys()
        deleted_count = 0
        
        for key in keys:
            try:
                if hasattr(done_repo, 'delete') and callable(done_repo.delete):
                    await done_repo.delete(key)
                    deleted_count += 1
                elif hasattr(done_repo, 'remove') and callable(done_repo.remove):
                    await done_repo.remove(key)
                    deleted_count += 1
                else:
                    logger.warning(f"Done repository for {node_id} does not support deletion")
                    raise HTTPException(status_code=501, detail="Repository does not support deletion")
            except Exception as e:
                logger.error(f"Error deleting key {key} from done repo in {node_id}: {e}")
                continue

        logger.info(f"Deleted {deleted_count} items from done repository for task {node_id}")
        
        # Get updated count after deletion
        remaining_keys = await done_repo.keys()
        remaining_count = len(remaining_keys)
        
        # Force cache refresh to update node statistics
        try:
            pipeline_interface.pipeline.cache_flush(soft=True)
        except Exception as e:
            logger.warning(f"Error flushing pipeline cache after deletion: {e}")
        
        return {
            "status": "success", 
            "deleted_count": deleted_count, 
            "remaining_count": remaining_count,
            "message": f"Deleted {deleted_count} items from done repository"
        }

    except Exception as e:
        logger.error(f"Error deleting done repository for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting done repository: {str(e)}")

@app.delete("/api/nodes/{node_id}/repos/done/{item_id}")
async def delete_done_repo_item(node_id: str, item_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    """Delete specific item from done repository for a node"""
    username = get_current_username(credentials, site_password)
    if node_id not in cache.nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    
    if pipeline_interface is None:
        raise HTTPException(status_code=503, detail="Pipeline interface not initialized")

    try:
        # Get the task object
        task_lookup = {task.name: task for task in pipeline_interface.pipeline.task_graph.nodes()}
        task = task_lookup.get(node_id)

        if not task:
            raise HTTPException(status_code=404, detail=f"Task {node_id} not found")

        if not hasattr(task, 'links') or 'done' not in task.links:
            raise HTTPException(status_code=404, detail=f"Task {node_id} has no 'done' repository")

        done_repo = task.links['done'].repo
        
        # Check if the item exists
        keys = await done_repo.keys()
        if item_id not in keys:
            raise HTTPException(status_code=404, detail=f"Item {item_id} not found in done repository")

        # Delete the specific item
        try:
            if hasattr(done_repo, 'delete') and callable(done_repo.delete):
                await done_repo.delete(item_id)
            elif hasattr(done_repo, 'remove') and callable(done_repo.remove):
                await done_repo.remove(item_id)
            else:
                logger.warning(f"Done repository for {node_id} does not support deletion")
                raise HTTPException(status_code=501, detail="Repository does not support deletion")
        except Exception as e:
            logger.error(f"Error deleting item {item_id} from done repo in {node_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Error deleting item: {str(e)}")

        logger.info(f"Deleted item {item_id} from done repository for task {node_id}")
        
        # Get updated count after deletion
        remaining_keys = await done_repo.keys()
        remaining_count = len(remaining_keys)
        
        # Force cache refresh to update node statistics
        try:
            pipeline_interface.pipeline.cache_flush(soft=True)
        except Exception as e:
            logger.warning(f"Error flushing pipeline cache after deletion: {e}")
        
        return {
            "status": "success", 
            "remaining_count": remaining_count,
            "message": f"Deleted item {item_id} from done repository"
        }

    except Exception as e:
        logger.error(f"Error deleting item {item_id} from done repository for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting item: {str(e)}")

def run_viz(pipeline, host, port, cycle_interval=30, debug=False, password="Hacking!"):
    """Entrypoint for "pd viz".

    Starts the visualizer and runs the dash server.
    
    Args:
        pipeline: The pipeline to visualize
        host: Host to bind to
        port: Port to bind to
        cycle_interval: Update interval in seconds
        debug: Whether to run in debug mode
        password: Password for accessing the visualization (if None, no password required)
    """
    global pipeline_interface
    global update_interval
    global site_password
    update_interval = cycle_interval
    site_password = password

    pipeline_interface = PipelineInterface(pipeline)
    import uvicorn
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_viz(None, host="0.0.0.0", port=8000)