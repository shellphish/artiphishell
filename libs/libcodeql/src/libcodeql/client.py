import asyncio
import functools
import json
import os
import sys
import time
from argparse import ArgumentParser
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, List, Tuple

import httpx
import yaml

CODEQL_SERVER_URL = os.getenv("CODEQL_SERVER_URL", "http://codeql:4000")

if os.getenv("CRS_TASK_NUM"):
    CODEQL_SERVER_URL = CODEQL_SERVER_URL.replace("TASKNUM", os.getenv("CRS_TASK_NUM"))
else:
    if "TASKNUM" in CODEQL_SERVER_URL:
        raise ValueError(
            "CRS_TASK_NUM is not set, but TASKNUM is in the CODEQL_SERVER_URL"
        )


def codeql_upload_db_cli():
    parser = ArgumentParser()
    parser.add_argument("--cp_name", type=str, required=True)
    parser.add_argument("--project_id", type=str, required=True)
    parser.add_argument("--language", type=str, required=True)
    parser.add_argument("--db_file", type=str, required=True)
    parser.add_argument("--base_url", type=str, default=CODEQL_SERVER_URL)
    args = parser.parse_args()

    client = CodeQLClient(args.base_url)
    result = client.upload_db(
        args.cp_name, args.project_id, args.language, args.db_file
    )
    print(result)


def codeql_upload_backup_cli():
    parser = ArgumentParser()
    parser.add_argument("backup_dir", type=lambda s: Path(s) if s is not None else None)
    parser.add_argument("--base-url", type=str, default=CODEQL_SERVER_URL)
    args = parser.parse_args()

    assert args.backup_dir and args.backup_dir.is_dir(), (
        f"Backup directory {args.backup_dir} does not exist"
    )

    client = CodeQLClient(args.base_url)
    dbs = (args.backup_dir / "codeql_build.codeql_database_path").glob("*.tar.gz")
    db_keys = []
    for db in dbs:
        db: Path
        print("Found database tarball:", db)
        # extract the db in to the folder
        db_dir = (
            args.backup_dir
            / "codeql_build.codeql_database_path"
            / db.name.split(".tar.gz")[0]
        )
        db_dir.mkdir(parents=True, exist_ok=True)
        os.system(f"tar -xf {db} -C {db_dir}")
        db_keys.append(db_dir.name)

    for key in db_keys:
        meta = args.backup_dir / "codeql_build.meta" / f"{key}.yaml"
        if not meta.exists():
            print(f"Meta file {meta} does not exist")
            continue
        with open(meta, "r") as f:
            data = yaml.safe_load(f)
            print(f"Processed data for {key}: {data}")
            cp_name = data["shellphish_project_name"]
            project_id = key
            language = data["language"]
            db_file = str(
                args.backup_dir
                / "codeql_build.codeql_database_path"
                / key
                / "sss-codeql-database.zip"
            )
            print(f"Uploading database for {cp_name} {project_id} {language} {db_file}")
        result = client.upload_db(cp_name, project_id, language, db_file)
        print(result)
        print(f"Uploaded database for {cp_name} {project_id} {language} {db_file}")


def codeql_query_cli():
    parser = ArgumentParser()
    parser.add_argument("--cp_name", type=str, required=True)
    parser.add_argument("--project_id", type=str, required=True)
    mutually_exclusive_group = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive_group.add_argument("--query_tmpl", type=str)
    mutually_exclusive_group.add_argument("--query_file", type=str)
    parser.add_argument("--query_params", type=str, default="{}")
    parser.add_argument("--base_url", type=str, default=CODEQL_SERVER_URL)
    parser.add_argument(
        "--timeout", type=int, default=-1, help="Timeout in seconds for the query"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="The path to a file to write the output to.",
    )
    args = parser.parse_args()

    assert not args.output or args.output.suffix in (".yaml", ".yml")

    client = CodeQLClient(args.base_url.rstrip("/"))
    request = {"cp_name": args.cp_name, "project_id": args.project_id}
    if args.query_tmpl:
        request["query_tmpl"] = args.query_tmpl
        request["query_params"] = json.loads(args.query_params)
    else:
        with open(args.query_file, "r") as f:
            request["query"] = f.read()
    if args.timeout > 0:
        request["timeout"] = args.timeout
    result = client.query(request)

    if args.output:
        with open(args.output, "w") as f:
            yaml.safe_dump(result, f)
            print(f"Results written to {args.output}")
    else:
        print(result)


def codeql_analyze_cli():
    parser = ArgumentParser()
    parser.add_argument("--cp_name", type=str, required=True)
    parser.add_argument("--project_id", type=str, required=True)
    parser.add_argument("--queries", type=str, nargs="*")
    parser.add_argument("--base_url", type=str, default=CODEQL_SERVER_URL)
    parser.add_argument(
        "--timeout", type=int, default=-1, help="Timeout in seconds for the analysis"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="The path to a file to write the output to.",
    )
    args = parser.parse_args()

    assert not args.output or args.output.suffix in (".sarif", ".json")

    client = CodeQLClient(args.base_url.rstrip("/"))
    request = {"cp_name": args.cp_name, "project_id": args.project_id}
    if args.queries:
        request["queries"] = args.queries
    if args.timeout > 0:
        request["timeout"] = args.timeout
    result = client.analyze(request)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f)
            print(f"Results written to {args.output}")
    else:
        print(result)


def async_or_sync(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with suppress(RuntimeError):
            asyncio.get_running_loop()
            return func(*args, **kwargs)
        return asyncio.run(func(*args, **kwargs))

    return wrapper


def exponential_backoff(
    max_retries: int = 6, base_delay: float = 5.0, max_delay: float = 120.0
):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except (httpx.HTTPError, ServerException) as e:
                    if isinstance(e, ServerException):
                        if func.__name__ == "_poll_task":
                            # If polling got server exception, raise it to the enclosing function
                            raise
                        if not any(
                            msg in str(e)
                            for msg in (
                                "Server process is not running",
                                "server might have crashed",
                            )
                        ):
                            # If the error is not related to server crash, raise it
                            raise
                    retries += 1
                    if retries > max_retries:
                        raise
                    delay = min(base_delay * (2 ** (retries - 1)), max_delay)

                    print(
                        f"Request failed with error: [{e}]. Retrying in {delay:.2f} seconds (attempt {retries}/{max_retries})",
                        file=sys.stderr,
                    )
                    await asyncio.sleep(delay)

        return wrapper

    return decorator


class ServerException(Exception):
    pass


sys.excepthook = (
    lambda exc_type, exc_value, exc_tb: print(
        f"{'=' * 31} ServerException {'=' * 31}\n{str(exc_value).strip()}\n{'=' * 79}",
        file=sys.stderr,
    )
    if issubclass(exc_type, ServerException)
    else sys.__excepthook__(exc_type, exc_value, exc_tb)
)


class CodeQLClient:
    def __init__(self, base_url: str = CODEQL_SERVER_URL, timeout: int = 3600):
        self.base_url = base_url
        self.timeout = httpx.Timeout(timeout)

    @async_or_sync
    @exponential_backoff()
    async def _poll_task(
        self,
        client: httpx.AsyncClient,
        task_id: str,
        poll_interval: int = 2,
        timeout: int = -1,
    ) -> Dict:
        start_time = time.time()
        while True:
            if timeout > 0 and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Task {task_id} timed out after {timeout} seconds")
            result = await client.get(f"{self.base_url}/task/{task_id}")
            task_status = result.json()

            if task_status["status"] == "completed":
                return task_status["result"]
            elif task_status["status"] == "failed":
                raise ServerException(task_status["result"])
            elif task_status["status"] == "not_found":
                raise ServerException(
                    f"Task {task_id} not found, server might have crashed while processing the task."
                )
            elif task_status["status"] == "processing":
                await asyncio.sleep(poll_interval)
            else:
                raise ServerException(
                    f"Unknown task status: {task_status} for task {task_id}"
                )

    @async_or_sync
    @exponential_backoff()
    async def upload_db(
        self, cp_name: str, project_id: str, language: str, db_file: str
    ):
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(db_file, "rb") as f:
                db_file = f.read()
            files = {"db_file": ("database.zip", db_file, "application/zip")}
            data = {"cp_name": cp_name, "project_id": project_id, "language": language}

            response = await client.post(
                f"{self.base_url}/upload_db", files=files, data=data
            )

            assert "task_id" in response.json(), (
                f"Server returned error: {response.text}"
            )
            task_id = response.json()["task_id"]
            return await self._poll_task(client, task_id)

    @async_or_sync
    @exponential_backoff()
    async def databases(self) -> Dict[str, Dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/databases",
            )
            return response.json()

    @async_or_sync
    @exponential_backoff()
    async def has_database(self, cp_name: str, project_id: str) -> bool:
        dbs = await self.databases()
        return cp_name in dbs and project_id in dbs[cp_name]

    @async_or_sync
    @exponential_backoff()
    async def get_database(self, cp_name: str, project_id: str) -> Dict[str, Any]:
        dbs = await self.databases()
        return dbs.get(cp_name, {}).get(project_id, {})

    @async_or_sync
    @exponential_backoff()
    async def query(self, task_data: Dict[str, Any], poll_interval: int = 2):
        if "timeout" not in task_data:
            task_data["timeout"] = 60 * 60
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.base_url}/query", json=task_data)

            assert "task_id" in response.json(), (
                f"Server returned error: {response.text}"
            )
            task_id = response.json()["task_id"]
            return await self._poll_task(client, task_id, poll_interval)

    @async_or_sync
    @exponential_backoff()
    async def analyze(self, task_data: Dict[str, Any], poll_interval: int = 2):
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.base_url}/analyze", json=task_data)

            assert "task_id" in response.json(), (
                f"Server returned error: {response.text}"
            )
            task_id = response.json()["task_id"]
            return await self._poll_task(client, task_id, poll_interval)
