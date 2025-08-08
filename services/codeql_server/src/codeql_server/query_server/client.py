import subprocess
from typing import Callable, Dict, Optional, Any, List
import asyncio
from pathlib import Path
import logging
from uuid import uuid4

from .server_process import ServerProcess
from .messages import *

logger = logging.getLogger("codeql")

class CodeQLError(Exception):
    def __init__(self, code: int, message: str, data: Optional[str] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"CodeQL Error {code}: {message}" + (f"\n{data}" if data else ""))

ProgressCallback = Callable[[int, int, str], None]

class QueryServerClient:
    def __init__(self, 
                 codeql_path: Path,
                 num_threads: int = 0,
                 ram_mb: int = 16384,
                 extra_args: Optional[List[str]] = None):
        self.codeql_path = codeql_path
        self.num_threads = num_threads
        self.ram_mb = ram_mb
        self.extra_args = extra_args if extra_args else []
        self.server_process: Optional[ServerProcess] = None
        self._response_handlers: Dict[int, asyncio.Future] = {}
        self._progress_callbacks: Dict[int, ProgressCallback] = {}
        self._message_handler_task = None
        self._request_id_to_progress_id: Dict[str, int] = {}
        self._next_progress_id = 0

    async def start_server(self):
        logger.debug(f"Starting CodeQL server with path: {self.codeql_path}")
        
        try:
            proc = subprocess.run(
                [str(self.codeql_path), "resolve", "ram", "--ram", str(self.ram_mb)],
                capture_output=True,
                text=True,
                check=True
            )
            ram_args = proc.stdout.strip().split()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to resolve RAM: {e.stderr}")
            ram_args = [f"-J-Xmx{self.ram_mb}M"]

        logger.info(f"Using RAM arguments: {ram_args}")

        args = [
            str(self.codeql_path),
            "execute",
            "query-server2",
            "--threads",
            str(self.num_threads),
        ]

        args.extend(ram_args)

        if self.extra_args:
            args.extend(self.extra_args)
        
        logger.debug(f"Executing command: {' '.join(args)}")
        
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            logger.error(f"Failed to start CodeQL process: {e}")
            raise

        # Add process verification
        await asyncio.sleep(1)  # Give process time to start
        if process.poll() is not None:
            stderr = await asyncio.get_event_loop().run_in_executor(
                None, process.stderr.read)
            raise RuntimeError(f"CodeQL process failed to start: {stderr.decode()}")

        self.server_process = ServerProcess(
            process=process,
            logger=logger,
            name="Query Server 2"
        )

        self._message_handler_task = asyncio.create_task(self._handle_messages())

    def _handle_error_response(self, msg: Dict) -> Exception:
        if "error" in msg:
            error = msg["error"]
            return CodeQLError(
                code=error.get("code", -1),
                message=error.get("message", "Unknown error"),
                data=error.get("data")
            )
        return RuntimeError("Unknown error in response")

    async def _handle_messages(self):
        logger.debug("Starting message handler loop")
        while True:
            try:
                msg = await self.server_process.receive_message()
                if msg is None:
                    continue
                
                logger.debug(f"Received message: {msg}")
                
                if "id" in msg:
                    request_id = msg["id"]
                    if request_id in self._response_handlers:
                        future = self._response_handlers.pop(request_id)
                            
                        if "error" in msg:
                            future.set_exception(self._handle_error_response(msg))
                        else:
                            result = msg.get("result", {})
                            if result.get("resultType") == QueryResultType.OTHER_ERROR:
                                future.set_exception(CodeQLError(
                                    code=QueryResultType.OTHER_ERROR,
                                    message=result.get("message", "Query execution failed"),
                                    data=None
                                ))
                            else:
                                future.set_result(result)
                elif "method" in msg and msg["method"] == "ql/progressUpdated":
                    params = msg["params"]
                    progress_id = params["id"]
                            
                    if progress_id in self._progress_callbacks:
                        self._progress_callbacks[progress_id](
                            params.get("step", 0),
                            params.get("maxStep", 100),
                            params.get("message", "")
                        )
            except Exception as e:
                logger.error(f"Error in message handler: {e}", exc_info=True)
                continue

    async def send_request(self, method: str, params: Any, request_id: Optional[str] = None,
                          progress_callback: Optional[ProgressCallback] = None,
                          timeout: int = None):
        if not self.server_process or not await self.server_process.is_alive():
            raise RuntimeError("Server process is not running")

        if request_id is None:
            request_id = str(uuid4())

        self._request_id_to_progress_id[request_id] = self._next_progress_id
        self._next_progress_id += 1
                
        if progress_callback:
            self._progress_callbacks[self._request_id_to_progress_id[request_id]] = progress_callback

        future = asyncio.Future()
        self._response_handlers[request_id] = future

        try:
            await self.server_process.send_message({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": {
                    "progressId": self._request_id_to_progress_id[request_id],
                    "body": params
                }
            })

            if timeout and timeout > 0:
                done, _ = await asyncio.wait([future], timeout=timeout)
                if future in done:
                    return future.result()
                else:
                    await self.cancel_request(request_id)
                    raise TimeoutError(f"Request {request_id} timed out after {timeout} seconds")
            else:
                return await future
        except Exception:
            raise
        finally:
            self._progress_callbacks.pop(self._request_id_to_progress_id[request_id], None)

    async def cancel_request(self, request_id: str):
        """Cancel a running request by its ID."""
        if not self.server_process or not await self.server_process.is_alive():
            raise RuntimeError("Server process is not running")
        
        try:
            await self.server_process.send_message({
                "jsonrpc": "2.0",
                "method": "$/cancelRequest",
                "params": {
                    "id": request_id
                }
            })
                    
        except Exception as e:
            logger.error(f"Failed to cancel request {request_id}: {e}")
            raise


    async def register_databases(self, databases: List[str]) -> None:
        """Register databases with the query server before use"""
        await self.send_request(
            "evaluation/registerDatabases",
            {"databases": databases}
        )

    async def get_database_info(self, db_path: str) -> DatabaseInfo:
        """Get information about a database"""
        result = await self.send_request(
            "evaluation/getDatabaseInfo",
            {"db": db_path}
        )
        return DatabaseInfo(**result)

    async def bqrs_info(self, bqrs_path: str) -> BqrsInfo:
        """Get information about a BQRS file"""
        result = await self.send_request(
            "evaluation/bqrsInfo",
            {"path": bqrs_path}
        )
        return BqrsInfo(**result)
    
    async def bqrs_decode(self, bqrs_path: str, result_set: str) -> BqrsResults:
        """Decode results from a BQRS result set"""
        result = await self.send_request(
            "evaluation/bqrsDecode",
            {
                "path": bqrs_path,
                "resultSet": result_set
            }
        )
        return BqrsResults(**result)
        
    async def get_ql_pack_info(self, pack_path: str) -> Dict[str, Any]:
        """Get information about a QL pack"""
        result = await self.send_request(
            "evaluation/getQlPackInfo",
            {"path": pack_path}
        )
        return result

    async def dispose(self):
        if self._message_handler_task:
            self._message_handler_task.cancel()
            try:
                await self._message_handler_task
            except asyncio.CancelledError:
                pass
            
        if self.server_process:
            await self.server_process.dispose()