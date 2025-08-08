import argparse
import asyncio
import hashlib
import io
import os
import base64
import glob
import json
import sqlite3
import subprocess
import logging
import tempfile
import traceback
import discord
from datetime import datetime
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, Body, Header, BackgroundTasks
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel, Field
import requests
import yaml


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("permanence_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("permanence_service")

# Constants
STORAGE_ROOT = os.environ.get("PERMANENCE_STORAGE_ROOT", "permanence_storage")
DB_PATH = os.environ.get("PERMANENCE_DB_PATH", "permanence.db")
API_SECRET = os.environ.get("PERMANENCE_API_SECRET", "!!artiphishell!!")

# Create storage directory if it doesn't exist
os.makedirs(STORAGE_ROOT, exist_ok=True)

# Initialize FastAPI app
app = FastAPI(title="Permanence Service", description="Backend service for storing fuzzing and patching campaign artifacts")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    print("INVALID REQUEST", request, exc)
    return PlainTextResponse(str(exc), status_code=400)


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS indexed_functions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        function_key TEXT NOT NULL,
        function_data TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        UNIQUE(project_name, function_key)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS grammar_reached_functions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        grammar_type TEXT NOT NULL,
        grammar TEXT NOT NULL,
        hit_functions TEXT NOT NULL,
        extra TEXT,
        timestamp TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS seeds_reached_functions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        seed_set_path TEXT NOT NULL,
        hit_functions TEXT NOT NULL,
        extra TEXT,
        timestamp TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS deduplicated_pov_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        report_path TEXT NOT NULL,
        seed_path TEXT NOT NULL,
        extra TEXT,
        timestamp TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS poi_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        report_path TEXT NOT NULL,
        extra TEXT,
        timestamp TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS patch_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        report_path TEXT NOT NULL,
        patch_path TEXT,
        functions_attempted TEXT NOT NULL,
        reasoning TEXT,
        successful INTEGER NOT NULL,
        timestamp TEXT NOT NULL
    )
    ''')

    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Dependency for authentication
async def verify_api_key(shellphish_secret: str = Header(None)):
    if shellphish_secret != API_SECRET:
        logger.warning(f"Unauthorized access attempt with wrong secret: found {shellphish_secret} instead of {API_SECRET}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    return shellphish_secret

# Helper functions
def get_timestamp():
    return datetime.now().isoformat()

def save_to_file(directory: str, filename: str, content: Any) -> str:
    """Save content to a file and return the path"""
    path = os.path.join(STORAGE_ROOT, directory)
    os.makedirs(path, exist_ok=True)

    full_path = os.path.join(path, filename)

    if isinstance(content, bytes):
        with open(full_path, 'wb') as f:
            f.write(content)
    else:
        with open(full_path, 'w') as f:
            if isinstance(content, (dict, list)):
                json.dump(content, f, indent=2)
            else:
                f.write(str(content))

    return full_path

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

async def async_run_shell_command(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Wait for the command to complete
    stdout, stderr = await proc.communicate()
    
    # Check if the command was successful
    if proc.returncode != 0:
        error_message = stderr.decode() if stderr else "Unknown error"
        raise Exception(f"Command failed with return code {proc.returncode}: {error_message}")
    
    return stdout.decode(), stderr.decode()

# Request logging middleware
# @app.middleware("http")
# async def log_requests(request: Request, call_next):
#     logger.info(f"Request: {request.method} {request.url.path}")

#     response = await call_next(request)
#     timestamp = time.time()
#     fname = f'{int(timestamp)}_{request.method}_{request.url.path.replace("/", "_").strip("_")}'
#     save_to_file("request-logs", fname + '.request.yaml', yaml.dump({
#         "method": request.method,
#         "url": str(request.url),
#         "query_params": dict(request.query_params),
#         "headers": dict(request.headers),
#         "body": await request.body()
#     }))
#     logger.info(f"Response: {response.status_code}")
#     save_to_file("request-logs", fname + '.response.yaml', yaml.dump({
#         "status_code": response.status_code,
#         "headers": dict(response.headers),
#     }))
#     return response

# Models
class Function(BaseModel):
    """Model for a function"""
    # This is just a placeholder - actual structure will come from client
    pass

class Extra(BaseModel):
    """Model for extra data"""
    # This is a flexible field for additional metadata
    pass

# Endpoint models
class IndexedFunctionsRequest(BaseModel):
    functions: Dict[str, Dict]

class GrammarReachedRequest(BaseModel):
    grammar_type: str
    grammar: str
    hit_functions: List[str]
    hit_files: List[str]
    extra: Optional[Dict[str, Any]] = None

class SeedsReachedRequest(BaseModel):
    seeds: List[str]  # base64 encoded
    hit_functions: List[str]
    hit_files: List[str]
    extra: Optional[Dict[str, Any]] = None

class DeduplicatedPovReportRequest(BaseModel):
    dedup_sanitizer_report: dict
    crashing_seed: str  # base64 encoded
    extra: Optional[Dict[str, Any]] = None

class PoiReportRequest(BaseModel):
    poi_report: dict
    extra: Optional[Dict[str, Any]] = None

class SuccessfulPatchRequest(BaseModel):
    poi_report: dict
    patch: str
    functions_attempted_to_patch: List[str]
    extra: Optional[Dict[str, Any]] = None

class UnsuccessfulPatchAttemptRequest(BaseModel):
    poi_report: dict
    reasoning: str
    functions_attempted_to_patch: List[str]

ALREADY_UPLOADED_INDEXED_FUNCTIONS = set()

def log_requests(f):
    """Decorator to log requests and responses"""
    import functools
    @functools.wraps(f)
    async def wrapper(*args, **kwargs):
        timestamp = time.time()
        fname = f'{int(timestamp)}_{f.__name__}'
        save_to_file("request-logs", fname + '.request.yaml', yaml.dump({
            "args": args,
            "kwargs": kwargs
        }))
        response = await f(*args, **kwargs)
        save_to_file("request-logs", fname + '.response.yaml', yaml.dump({
            "response": response
        }))
        return response
    return wrapper

def normalize_for_path(func_key: str) -> str:
    """Normalize function index key to a consistent format"""
    # filenames are limited to 255 characters only.
    # so, this means first, we replace all '/' with '_'
    # then, we only take the last 255-len(sha1(func_key)) characters and append the sha1
    # of the function key to ensure uniqueness
    # and avoid any potential collisions
    func_key = func_key.replace('/', '_')
    if len(func_key) < 200:
        return func_key
    sha1_hash = hashlib.sha1(func_key.encode()).hexdigest()
    func_key = func_key[-(200 - len(sha1_hash)):] + sha1_hash
    return func_key

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", None)
def send_discord_webhook(title: str, description: str, files: Optional[List[Path]] = None):
    try:
        from discord import SyncWebhook

        webhook = SyncWebhook.from_url(DISCORD_WEBHOOK_URL)
        webhook.send(
            content=f'**New Discovery!**',
            username="Permanence Service",
            avatar_url="https://example.com/avatar.png",  # Placeholder for avatar URL
            embeds=[
                discord.Embed(
                    title=title,
                    description=description,
                    color=0x00ff00  # Green color
                )
            ],
            files=[discord.File(file) for file in files] if files else []
        )
    except Exception as e:
        logger.error(f"Failed to send Discord webhook: {str(e)}", exc_info=True)



discoveries_to_flush = []
def register_novel_discovery(type, message, *args, submission_metadata=None, **kwargs):
    # First, yell LOUDLY that this happened!!!
    logger.info(f"################################### Novel {type} discovery: {message}! ########################################")
    logger.info(f"### {message}: {args=}\n{kwargs=}\n{submission_metadata=}\n")
    logger.info("#######################################################################################################")
    # Then, save it to a file for later analysis
    timestamp = get_timestamp()
    fname = f'{timestamp}.log'
    save_to_file(f"novel_discoveries/{type}", fname, yaml.dump({
        "timestamp": timestamp,
        "message": message,
        "args": args,
        "kwargs": kwargs,
        "submission_metadata": submission_metadata
    }))
    # Also, append it to the novel discoveries log file
    with open(os.path.join(STORAGE_ROOT, f"novel_discoveries.log"), 'a') as f:
        f.write(f'{timestamp} - {type} - {message}: {args=} {kwargs=} {submission_metadata=}\n')
    with open(os.path.join(STORAGE_ROOT, f"novel_discoveries.jsonl"), 'a') as f:
        f.write(json.dumps({
            "timestamp": timestamp,
            "type": type,
            "message": message,
            "args": args,
            "kwargs": kwargs,
            "submission_metadata": submission_metadata
        }) + '\n')
    # Finally, return the filename for reference
    with tempfile.NamedTemporaryFile(delete=False) as submission_meta_file:
        submission_meta = yaml.safe_dump({
            "timestamp": timestamp,
            "message": message,
            **(submission_metadata if submission_metadata else {}),
            **kwargs,
        })
        submission_meta_file.write(submission_meta.encode())


        submission_meta_message = {
            "timestamp": timestamp,
            "message": message,
            **(submission_metadata if submission_metadata else {}),
            **kwargs,
        }
        submission_meta_message.pop('grammar', None)
        submission_meta_message = yaml.safe_dump(submission_meta_message, sort_keys=False)
        if len(submission_meta_message) < 1000:
            submission_meta_message = f"\n\nSubmission metadata: ```yaml\n{submission_meta_message}```"
            upload_submission_meta = False
        else:
            submission_meta_message = f"\n\nSubmission metadata: ```yaml\n{submission_meta_message[:1000]}... (truncated)```"
            upload_submission_meta = True

        # Add additional logic to handle submission_meta_in_message if needed
        logger.info(f"Submission metadata in message: {submission_meta_message}")

        # Lastly, if we have a webhook URL, send the discovery to it
        if DISCORD_WEBHOOK_URL:
            # send a discord message announcing our fantastic new discovery!!!!!!! Hype that up!!! Emojis and everything!!!
            if type == 'novel_grammar_coverage':
                project_name = kwargs.get('project_name')
                harness_name = kwargs.get('harness_name')
                grammar_path = kwargs.get('grammar_path')
                novel_functions = kwargs.get('novel_functions')
                novel_files = kwargs.get('novel_files')
                # Send the notification to Discord with the grammar attached as a file
                files = [grammar_path] + ([submission_meta_file.name] if upload_submission_meta else [])
                send_discord_webhook(
                    title=f"🧬 [{project_name}:{harness_name}] New grammar coverage: {len(novel_functions)} functions and {len(novel_files)} files.",
                    description=message + submission_meta_message,
                    files=files,
                )
            elif type == 'novel_seed_coverage':
                project_name = kwargs.get('project_name')
                harness_name = kwargs.get('harness_name')
                seed_set_dir = kwargs.get('seeds_dir')
                novel_files = kwargs.get('novel_files')
                novel_functions = kwargs.get('novel_functions')
                # Send the notification to Discord with the seed set directory attached as a file
                files = [os.path.join(seed_set_dir, f) for f in os.listdir(seed_set_dir)]
                files = files[:3] + ([submission_meta_file.name] if upload_submission_meta else [])  # Limit to 3 files for the webhook
                send_discord_webhook(
                    title=f"🌱 [{project_name}:{harness_name}] New seed coverage: {len(novel_functions)} funcs, {len(novel_files)} files.",
                    description=message + submission_meta_message,
                    files=files
                )

    return os.path.join(STORAGE_ROOT, f"novel_discoveries/{type}", fname)

# Routes
@app.post("/indexed_functions/{project_name}")
@log_requests
async def upload_indexed_functions(
    project_name: str,
    data: IndexedFunctionsRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received indexed functions for project: {project_name}")

    timestamp = get_timestamp()

    try:
        # Store functions in the database
        hashes = {key: hashlib.md5(json.dumps(func_data, sort_keys=True).encode()).hexdigest() for key, func_data in data.functions.items()}
        new_hashes = {key: hash for key, hash in hashes.items() if hash not in ALREADY_UPLOADED_INDEXED_FUNCTIONS}
        if new_hashes:
            for func_key, hash in new_hashes.items():
                logger.info(f"[indexed_functions] Saving newly discovered function hash {hash} for function {func_key}")
                func_dir = os.path.join(project_name, "functions")
                func_data = data.functions[func_key]
                save_to_file(func_dir, f"{hash}.json", func_data)

        for func_key, hash in hashes.items():
            if (func_key, hash) not in ALREADY_UPLOADED_INDEXED_FUNCTIONS:
                # create a symlink to the hashed json file
                ALREADY_UPLOADED_INDEXED_FUNCTIONS.add((func_key, hash))
                logger.info(f"[indexed_functions] Saving function {func_key} with hash {hash} to database")
                os.symlink(f"{hash}.json", os.path.join(STORAGE_ROOT, project_name, "functions", f"{normalize_for_path(func_key)}_{timestamp}.json"))
        return {"status": "success", "timestamp": timestamp}

    except Exception as e:
        logger.error(f"Error saving indexed functions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving indexed functions: {str(e)}")


@app.post("/grammar_reached/{project_name}/{harness_name}")
@log_requests
async def grammar_reached_functions(
    project_name: str,
    harness_name: str,
    data: GrammarReachedRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received grammar reached functions for {project_name}/{harness_name}")

    timestamp = get_timestamp()

    fully_novel_files = []
    fully_novel_funcs = []
    try:
        # Save grammar to filesystem
        grammar_dir = os.path.join(project_name, harness_name, "grammars")
        grammar_hash = hashlib.md5(data.grammar.encode()).hexdigest()
        grammar_ident = f'{data.grammar_type}_{grammar_hash}'
        grammar_path = save_to_file(grammar_dir, f"{grammar_ident}.txt", data.grammar)
        reached_path = save_to_file(grammar_dir, f'{grammar_ident}.{timestamp}.json', data.model_dump_json(indent=2))

        for function in data.hit_functions:
            # Normalize function index key and save to database
            normalized_key = normalize_for_path(function)
            func_dir = os.path.join(STORAGE_ROOT, os.path.join(project_name, harness_name, "functions", "reaching_grammars", normalized_key))
            os.makedirs(func_dir, exist_ok=True)
            os.symlink(f'../../../grammars/{grammar_ident}.txt', os.path.join(func_dir, f"{timestamp}.txt"))
            if not os.path.exists(os.path.join(func_dir, f"normalized.json")):
                fully_novel_funcs.append(function)
            with open(os.path.join(func_dir, f"normalized.json"), 'w') as f:
                json.dump({"function_key": function}, f, indent=2)
        # Save hit files list
        for hit_file in data.hit_files:
            # Normalize file path and save to database
            normalized_file_path = normalize_for_path(hit_file)
            file_dir = os.path.join(STORAGE_ROOT, os.path.join(project_name, harness_name, "files", "reaching_grammars", normalized_file_path))
            os.makedirs(file_dir, exist_ok=True)
            os.symlink(f'../../../grammars/{grammar_ident}.txt', os.path.join(file_dir, f"{timestamp}.txt"))
            if not os.path.exists(os.path.join(file_dir, f"normalized.json")):
                fully_novel_files.append(hit_file)
            with open(os.path.join(file_dir, f"normalized.json"), 'w') as f:
                json.dump({"file_path": hit_file}, f, indent=2)

        if fully_novel_files or fully_novel_funcs:
            message = f"Grammar {grammar_ident} at {timestamp} newly reached {len(fully_novel_funcs)} functions and {len(fully_novel_files)} files."
            # Register the novel discovery
            register_novel_discovery(
                "novel_grammar_coverage",
                message,
                project_name=project_name,
                harness_name=harness_name,
                grammar_path=grammar_path,
                novel_functions=fully_novel_funcs,
                novel_files=fully_novel_files,
                submission_metadata={
                    'novel_functions': fully_novel_funcs if fully_novel_funcs else [],
                    'novel_files': fully_novel_files if fully_novel_files else [],
                    'grammar_type': data.grammar_type,
                    'grammar_hash': grammar_hash,
                    **(data.extra if data.extra else {}),
                }
            )

        return {
            "status": "success",
            "timestamp": timestamp,
            "grammar_path": grammar_path,
            "grammar_hash": grammar_hash,
            "reached_path": reached_path
        }

    except Exception as e:
        logger.error(f"Error saving grammar reached functions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving grammar reached functions: {str(e)}")


@app.post("/seeds_reached/{project_name}/{harness_name}")
@log_requests
async def seeds_reached(
    project_name: str,
    harness_name: str,
    data: SeedsReachedRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received seeds and reached functions for {project_name}/{harness_name}: {len(data.seeds)} seeds reached {len(data.hit_functions)} functions")
    if not data.seeds:
        raise HTTPException(status_code=400, detail="No seeds provided")
    if not data.hit_functions:
        raise HTTPException(status_code=400, detail="No hit functions provided")

    timestamp = get_timestamp()

    fully_novel_files = []
    fully_novel_funcs = []
    try:
        # Decode seed from base64
        seed_bytes = [base64.b64decode(s) for s in data.seeds]

        cur_seed_set_dir = os.path.join(project_name, harness_name, f'seeds_sets/{timestamp}')
        seed_paths = []
        # Save seed to filesystem
        for i, seed in enumerate(seed_bytes):
            seed_filename = f"seed_{i}.bin"
            seed_path = save_to_file(cur_seed_set_dir, seed_filename, seed)
            seed_paths.append(seed_path)

        # Save hit functions list
        save_to_file(cur_seed_set_dir, "hit_functions.json", json.dumps(data.hit_functions, indent=2))
        save_to_file(cur_seed_set_dir, "hit_files.json", json.dumps(data.hit_files, indent=2))
        save_to_file(cur_seed_set_dir, "seed_set.json", json.dumps({"seeds": seed_paths, "hit_functions": data.hit_functions, "hit_files": data.hit_files}, indent=2))

        # Save to per-function directories
        for hit_func in data.hit_functions:
            # Normalize function index key and save symlink to the seedset
            normalized_key = normalize_for_path(hit_func)
            func_dir = os.path.join(STORAGE_ROOT, os.path.join(project_name, harness_name, "functions", "reaching_seed_sets", normalized_key))
            os.makedirs(func_dir, exist_ok=True)
            os.symlink(f'../../../seeds_sets/{timestamp}', os.path.join(func_dir, f"{timestamp}"))
            if not os.path.exists(os.path.join(func_dir, f"normalized.json")):
                fully_novel_funcs.append(hit_func)
            with open(os.path.join(func_dir, f"normalized.json"), 'w') as f:
                json.dump({"function_key": hit_func}, f, indent=2)

        # Save hit files list
        for hit_file in data.hit_files:
            # Normalize file path and save symlink to the seedset
            normalized_file_path = normalize_for_path(hit_file)
            file_dir = os.path.join(STORAGE_ROOT, os.path.join(project_name, harness_name, "files", "reaching_seed_sets", normalized_file_path))
            os.makedirs(file_dir, exist_ok=True)
            os.symlink(f'../../../seeds_sets/{timestamp}', os.path.join(file_dir, f"{timestamp}"))
            if not os.path.exists(os.path.join(file_dir, f"normalized.json")):
                fully_novel_files.append(hit_file)
            with open(os.path.join(file_dir, f"normalized.json"), 'w') as f:
                json.dump({"file_path": hit_file}, f, indent=2)

        if fully_novel_files or fully_novel_funcs:
            message = f"Seeds {timestamp} newly reached: {len(fully_novel_funcs)} functions and {len(fully_novel_files)} files."
            # Register the novel discovery
            register_novel_discovery(
                "novel_seed_coverage",
                message,
                project_name=project_name,
                harness_name=harness_name,
                seeds_dir=os.path.join(STORAGE_ROOT, cur_seed_set_dir),
                novel_functions=fully_novel_funcs,
                novel_files=fully_novel_files,
                submission_metadata={
                    'novel_functions': fully_novel_funcs if fully_novel_funcs else [],
                    'novel_files': fully_novel_files if fully_novel_files else [],
                    **(data.extra if data.extra else {}),
                }
            )
        return {
            "status": "success",
            "timestamp": timestamp,
            "seed_set_dir": cur_seed_set_dir,
        }

    except Exception as e:
        logger.error(f"Error saving seed reached functions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving seed reached functions: {str(e)}")

@app.post("/deduplicated_pov_report/{project_name}/{harness_name}")
@log_requests
async def deduplicated_pov_report(
    project_name: str,
    harness_name: str,
    data: DeduplicatedPovReportRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received deduplicated POV report for {project_name}/{harness_name}")

    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = get_timestamp()

    try:
        # Save report to filesystem
        reports_dir = os.path.join(project_name, harness_name, "pov_reports")
        report_filename = f"dedup_report_{timestamp}.json"
        report_path = save_to_file(reports_dir, report_filename, data.dedup_sanitizer_report)

        # Decode and save crashing seed
        seed_bytes = base64.b64decode(data.crashing_seed)
        seed_filename = f"crashing_seed_{timestamp}.bin"
        seed_path = save_to_file(reports_dir, seed_filename, seed_bytes)

        # Save to database
        cursor.execute(
            """
            INSERT INTO deduplicated_pov_reports
            (project_name, harness_name, report_path, seed_path, extra, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                project_name,
                harness_name,
                report_path,
                seed_path,
                json.dumps(data.extra) if data.extra else None,
                timestamp
            )
        )

        conn.commit()
        return {
            "status": "success",
            "timestamp": timestamp,
            "report_path": report_path,
            "seed_path": seed_path
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving deduplicated POV report: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving deduplicated POV report: {str(e)}")

    finally:
        conn.close()

@app.post("/poi_report/{project_name}/{harness_name}")
@log_requests
async def poi_report(
    project_name: str,
    harness_name: str,
    data: PoiReportRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received POI report for {project_name}/{harness_name}")

    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = get_timestamp()

    try:
        # Save report to filesystem
        reports_dir = os.path.join(project_name, harness_name, "poi_reports")
        report_filename = f"poi_report_{timestamp}.json"
        report_path = save_to_file(reports_dir, report_filename, data.poi_report)

        # Save to database
        cursor.execute(
            """
            INSERT INTO poi_reports
            (project_name, harness_name, report_path, extra, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                project_name,
                harness_name,
                report_path,
                json.dumps(data.extra) if data.extra else None,
                timestamp
            )
        )

        conn.commit()
        return {"status": "success", "timestamp": timestamp, "report_path": report_path}

    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving POI report: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving POI report: {str(e)}")

    finally:
        conn.close()

@app.post("/successful_patch/{project_name}/{harness_name}")
@log_requests
async def successful_patch(
    project_name: str,
    harness_name: str,
    data: SuccessfulPatchRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received successful patch for {project_name}/{harness_name}")

    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = get_timestamp()

    try:
        # Save report to filesystem
        patch_dir = os.path.join(project_name, harness_name, "patches")

        # Save POI report
        report_filename = f"poi_report_{timestamp}.json"
        report_path = save_to_file(patch_dir, report_filename, data.poi_report)

        # Save patch
        patch_filename = f"successful_patch_{timestamp}.patch"
        patch_path = save_to_file(patch_dir, patch_filename, data.patch)

        # Save attempted functions
        funcs_filename = f"patched_functions_{timestamp}.json"
        save_to_file(patch_dir, funcs_filename, data.functions_attempted_to_patch)

        # Save to database
        cursor.execute(
            """
            INSERT INTO patch_attempts
            (project_name, harness_name, report_path, patch_path, functions_attempted, successful, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_name,
                harness_name,
                report_path,
                patch_path,
                json.dumps(data.functions_attempted_to_patch),
                1,  # successful
                timestamp
            )
        )

        conn.commit()
        return {
            "status": "success",
            "timestamp": timestamp,
            "report_path": report_path,
            "patch_path": patch_path
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving successful patch: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving successful patch: {str(e)}")

    finally:
        conn.close()

@app.post("/unsuccessful_patch_attempt/{project_name}/{harness_name}")
@log_requests
async def unsuccessful_patch_attempt(
    project_name: str,
    harness_name: str,
    data: UnsuccessfulPatchAttemptRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Received unsuccessful patch attempt for {project_name}/{harness_name}")

    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = get_timestamp()

    try:
        # Save report to filesystem
        patch_dir = os.path.join(project_name, harness_name, "patches")

        # Save POI report
        report_filename = f"poi_report_{timestamp}.json"
        report_path = save_to_file(patch_dir, report_filename, data.poi_report)

        # Save reasoning
        reason_filename = f"unsuccessful_patch_reasoning_{timestamp}.txt"
        save_to_file(patch_dir, reason_filename, data.reasoning)

        # Save attempted functions
        funcs_filename = f"attempted_functions_{timestamp}.json"
        save_to_file(patch_dir, funcs_filename, data.functions_attempted_to_patch)

        # Save to database
        cursor.execute(
            """
            INSERT INTO patch_attempts
            (project_name, harness_name, report_path, functions_attempted, reasoning, successful, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_name,
                harness_name,
                report_path,
                json.dumps(data.functions_attempted_to_patch),
                data.reasoning,
                0,  # unsuccessful
                timestamp
            )
        )

        conn.commit()
        return {"status": "success", "timestamp": timestamp, "report_path": report_path}

    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving unsuccessful patch attempt: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error saving unsuccessful patch attempt: {str(e)}")

    finally:
        conn.close()

@app.get("/download_grammars/{project_name}/{harness_name}")
async def download_project_harness_grammars(
    project_name: str,
    harness_name: str,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    # if there is no project_name directory, return error 500
    if not os.path.exists(os.path.join(STORAGE_ROOT, project_name)):
        logger.error(f"Project {project_name} not found")
        raise HTTPException(status_code=500, detail="Project not found")

    try:
        logger.info(f"Downloading grammars for project: {project_name}, harness: {harness_name}")
        grammar_pattern = os.path.join("*", project_name, harness_name, "grammars", "*")
        fd, archive_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        cmd = f"""TMPDIR=$(mktemp -d) && find {STORAGE_ROOT} -path "{grammar_pattern}" -name "*.txt" -type f -print0 | xargs -0 md5sum | sort -k1,1 -u | while IFS=" " read -r hash file; do cp "$file" $TMPDIR/$hash; done && tar -czf {archive_path} -C $TMPDIR . && rm -rf $TMPDIR"""
        await async_run_shell_command(cmd)

        # Schedule temp-file removal after response
        background_tasks.add_task(os.remove, archive_path)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        return FileResponse(
            path=archive_path,
            filename=f"{harness_name}_grammars_{timestamp}.tar",
            media_type="application/x-tar"
        )
    except Exception as ex:
        os.remove(archive_path)
        logger.exception("Failed to build grammar archive")
        raise HTTPException(status_code=500, detail=f"Failed to build grammar archive: {str(ex)} {traceback.format_exc()}")

@app.get("/download_corpus/{project_name}/{harness_name}")
async def download_project_harness_corpus(
    project_name: str,
    harness_name: str,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    # if there is no project_name directory, return error 500
    if not os.path.exists(os.path.join(STORAGE_ROOT, project_name)):
        logger.error(f"Project {project_name} not found")
        raise HTTPException(status_code=500, detail="Project not found")

    try:
        logger.info(f"Downloading corpus for project: {project_name}, harness: {harness_name}")
        harness_pattern = os.path.join("*", project_name, harness_name, "seeds_sets", "*")
        fd, archive_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        cmd = f"""TMPDIR=$(mktemp -d) && find {STORAGE_ROOT} -path "{harness_pattern}" -name "*.bin" -type f -print0 | xargs -0 md5sum | sort -k1,1 -u | while IFS=" " read -r hash file; do cp "$file" $TMPDIR/$hash; done && tar -czf {archive_path} -C $TMPDIR . && rm -rf $TMPDIR"""
        await async_run_shell_command(cmd)
        
        # Schedule temp-file removal after response
        background_tasks.add_task(os.remove, archive_path)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        return FileResponse(
            path=archive_path,
            filename=f"{harness_name}_corpus_{timestamp}.tar",
            media_type="application/x-tar"
        )
    except Exception as ex:
        os.remove(archive_path)
        logger.exception("Failed to build corpus archive")
        raise HTTPException(status_code=500, detail=f"Failed to build corpus archive: {str(ex)} {traceback.format_exc()}")

@app.get("/download_corpus/{harness_name}")
async def download_harness_corpus(
    harness_name: str,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    # if there is no dir named */harness_name, return error 500
    if not glob.glob(os.path.join(STORAGE_ROOT, "*", harness_name)):
        logger.error(f"Harness {harness_name} not found")
        raise HTTPException(status_code=500, detail="Harness not found")

    try:
        logger.info(f"Downloading corpus for harness: {harness_name}")
        harness_pattern = os.path.join("*", "*", harness_name, "seeds_sets", "*")
        fd, archive_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        cmd = f"""TMPDIR=$(mktemp -d) && find {STORAGE_ROOT} -path "{harness_pattern}" -name "*.bin" -type f -print0 | xargs -0 md5sum | sort -k1,1 -u | while IFS=" " read -r hash file; do cp "$file" $TMPDIR/$hash; done && tar -cf {archive_path} -C $TMPDIR . && rm -rf $TMPDIR"""
        await async_run_shell_command(cmd)
            
        # Schedule temp-file removal after response
        background_tasks.add_task(os.remove, archive_path)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        return FileResponse(
            path=archive_path,
            filename=f"{harness_name}_corpus_{timestamp}.tar",
            media_type="application/x-tar"
        )
    except Exception:
        os.remove(archive_path)
        logger.exception("Failed to build corpus archive")
        raise HTTPException(status_code=500, detail="Failed to build corpus archive")

# Stats and status routes
@app.get("/status")
async def status(api_key: str = Depends(verify_api_key)):
    """Get service status and basic stats"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        stats = {}

        # Count records in each table
        tables = [
            "deduplicated_pov_reports",
            "poi_reports",
            "patch_attempts"
        ]

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]

        # Get projects
        cursor.execute("SELECT DISTINCT project_name FROM indexed_functions")
        stats["projects"] = [row[0] for row in cursor.fetchall()]

        # Get disk usage
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(STORAGE_ROOT):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)

        stats["storage_size_bytes"] = total_size
        stats["storage_size_mb"] = round(total_size / (1024 * 1024), 2)

        return {
            "status": "running",
            "version": "1.0.0",
            "timestamp": get_timestamp(),
            "stats": stats
        }

    except Exception as e:
        logger.error(f"Error getting status: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting status: {str(e)}")

    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="Permanence Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=31337, help="Port to bind to")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    logger.info(f"Starting Permanence Service on {args.host}:{args.port}")
    logger.info(f"Storage root: {STORAGE_ROOT}")
    logger.info(f"Database path: {DB_PATH}")

    uvicorn.run(app, host=args.host, port=args.port)
