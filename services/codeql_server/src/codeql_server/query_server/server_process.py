import subprocess
from typing import Optional, Dict, Any
from logging import Logger
import json
import asyncio
import dataclasses
from enum import Enum
from pathlib import Path

def to_json_serializable(obj):
    if hasattr(obj, 'to_dict'):
        return to_json_serializable(obj.to_dict())
    elif dataclasses.is_dataclass(obj):
        return to_json_serializable(dataclasses.asdict(obj))
    elif isinstance(obj, dict):
        return {k: to_json_serializable(v) for k, v in obj.items() 
                if v is not None}
    elif isinstance(obj, (list, tuple)):
        return [to_json_serializable(x) for x in obj]
    elif isinstance(obj, Enum):
        return obj.value
    elif isinstance(obj, Path):
        return str(obj)
    return obj

class ServerProcess:
    def __init__(self, process: subprocess.Popen, logger: Logger, name: str):
        self.process = process
        self.logger = logger
        self.name = name
        self._stdin_queue = asyncio.Queue()
        self._stdout_queue = asyncio.Queue()
        self._stderr_queue = asyncio.Queue()
        self._is_running = True
        self._lock = asyncio.Lock()
        
        self.logger.debug(f"Initializing {name} server process")
        
        # Start reader/writer tasks
        self._start_io_tasks()

    def _start_io_tasks(self):
        async def stdout_reader():
            self.logger.debug("Starting stdout reader")
            while self._is_running:
                try:
                    # Read headers first
                    content_length = 0
                    while True:
                        header = await asyncio.get_event_loop().run_in_executor(
                            None, self.process.stdout.readline)
                        if not header:
                            self.logger.debug("Received EOF on stdout")
                            self._is_running = False
                            return
                        header = header.strip().decode()
                        if not header:  # Empty line marks end of headers
                            break
                        if header.startswith('Content-Length: '):
                            content_length = int(header.split(': ')[1])
                    
                    if content_length > 0:
                        # Read exact number of bytes for the message
                        content = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: self.process.stdout.read(content_length))
                        if not content:
                            break
                        
                        try:
                            msg = json.loads(content)
                            await self._stdout_queue.put(msg)
                        except json.JSONDecodeError:
                            self.logger.error(f"Failed to parse JSON: {content}")
                except Exception as e:
                    self.logger.error(f"Error reading from process: {e}", exc_info=True)
                    break
            self._is_running = False
            self.logger.debug("Stdout reader stopped")

        async def stdin_writer():
            while self._is_running:
                try:
                    msg = await asyncio.wait_for(self._stdin_queue.get(), timeout=1)
                    if msg is None:
                        break
                    try:
                        json_str = json.dumps(msg)
                        headers = (
                            f"Content-Length: {len(json_str)}\r\n"
                            "Content-Type: application/json\r\n"
                            "\r\n"
                        )
                        
                        # Write headers and content
                        await asyncio.get_event_loop().run_in_executor(
                            None, lambda: self.process.stdin.write(headers.encode()))
                        await asyncio.get_event_loop().run_in_executor(
                            None, lambda: self.process.stdin.write(json_str.encode()))
                        await asyncio.get_event_loop().run_in_executor(
                            None, self.process.stdin.flush)
                    except Exception as e:
                        self.logger.error(f"Error writing to process: {e}")
                        break
                except asyncio.TimeoutError:
                    continue
            self._is_running = False

        async def stderr_reader():
            self.logger.debug("Starting stderr reader")
            while self._is_running:
                try:
                    line = await asyncio.get_event_loop().run_in_executor(
                        None, self.process.stderr.readline)
                    if not line:
                        break
                    self.logger.info(line.strip().decode())
                except Exception as e:
                    self.logger.error(f"Error reading stderr: {e}")
                    break

        loop = asyncio.get_event_loop()
        self._reader_task = loop.create_task(stdout_reader())
        self._writer_task = loop.create_task(stdin_writer())
        self._stderr_task = loop.create_task(stderr_reader())

    async def is_alive(self) -> bool:
        return self.process.poll() is None

    async def send_message(self, message: Dict[str, Any], timeout: float = 5.0) -> None:
        if not self._is_running or not await self.is_alive():
            raise RuntimeError(f"Server process is not running (pid={self.process.pid})")
        
        self.logger.debug(f"Sending message: {message}")
        serialized = to_json_serializable(message)
        await asyncio.wait_for(self._stdin_queue.put(serialized), timeout=timeout)

    async def receive_message(self, timeout: Optional[float] = 5.0) -> Optional[Dict[str, Any]]:
        if not self._is_running:
            raise RuntimeError("Server process is not running")
            
        try:
            return await asyncio.wait_for(self._stdout_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def dispose(self):
        async with self._lock:
            if not self._is_running:
                return
                
            self._is_running = False
            
            # Signal writer to stop
            await self._stdin_queue.put(None)
            
            # Cancel tasks
            self._reader_task.cancel()
            self._writer_task.cancel()
            if hasattr(self, '_stderr_task'):
                self._stderr_task.cancel()
                try:
                    await self._stderr_task
                except asyncio.CancelledError:
                    pass
            
            try:
                await asyncio.gather(self._reader_task, self._writer_task, 
                                   return_exceptions=True)
            except asyncio.CancelledError:
                pass

            # Close pipes
            if self.process.stdin:
                self.process.stdin.close()
            if self.process.stdout:
                self.process.stdout.close()
            if self.process.stderr:
                self.process.stderr.close()
            
            # Terminate process
            self.process.terminate()
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.process.wait(timeout=5))
            except subprocess.TimeoutExpired:
                self.process.kill()
                await asyncio.get_event_loop().run_in_executor(
                    None, self.process.wait)
            
            self.logger.info(f"Stopped {self.name}")