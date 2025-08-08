import time
import json
import socket
import logging
import select

from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from debug_lib.debuggers.debugger import Debugger
from debug_lib.debuggers.context import BacktraceLine, Variable, Frame, Breakpoint

log = logging.getLogger("jdb")
log.setLevel(logging.INFO)

class JDBServerResponseStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"

@dataclass
class JDBServerResponse:
    status: JDBServerResponseStatus
    data: str

    @classmethod
    def from_dict(cls, data: dict):
        status = data["status"]
        if status == "success":
            return cls(status=JDBServerResponseStatus.SUCCESS, data=data.get("data", ""))
        elif status == "error":
            return cls(status=JDBServerResponseStatus.ERROR, data=data.get("data", ""))
        else:
            raise ValueError(f"Invalid status: {status}")

    def __str__(self):
        return f"JDBServerResponse(status={self.status}, data={self.data})"

    def __repr__(self):
        return self.__str__()
    
    @property
    def is_success(self):
        return self.status == JDBServerResponseStatus.SUCCESS
    
    @property
    def is_error(self):
        return self.status == JDBServerResponseStatus.ERROR
    
class JavaDebugger(Debugger):
    def __init__(self, binary: Path, remote, argv: list = None, classpath: list[Path] = None, source_path: Path = None, class_name: str = None, **kwargs):
        super().__init__(binary, **kwargs)
        self.binary = binary
        self.remote = remote
        self.source_path = source_path
        self.class_name = class_name
        self.class_path = classpath
        self.argv = argv if argv is not None else []
        self._controller = None
        self._exit_code: int
        self._debugger_stdout: List[str] = []
        self._has_started = False
        self._cmd_ready = False
        self.exited = True
        self._current_thread = None
        self._init_controller()
    
    @property
    def is_connected(self):
        return self._controller is not None
    
    @property
    def is_live(self):
        return self.is_connected and not self.exited
    
    def _init_remote_conn(self):
        remote_ip, remote_port = self.remote.split(":")
        log.info("[*] Connecting to %s:%s", remote_ip, remote_port)
        time.sleep(5)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((remote_ip, int(remote_port)))
        log.info("[+] Connected to %s:%s", remote_ip, remote_port)
        self._controller = conn
        self.exited = False

    def _init_controller(self):
        if self._controller is not None:
            return
        # Connect to IP:PORT in the remote
        self._init_remote_conn()
        for _ in range(10):
            try:
                resp = self.load_binary()
                if resp.status == JDBServerResponseStatus.SUCCESS:
                    log.info("[+] Binary loaded successfully")
                    break
            except ConnectionError as e:
                log.info("[*] Retrying to connect to the controller")
                log.info("[*] Error: %s", e)
            time.sleep(1)

    def _disconnect_controller(self):
        if self._controller is not None:
            self._controller.close()
            self._controller = None
            log.info("[*] Disconnected from the controller")
    
    def send_cmd(self, cmd: dict) -> Optional[JDBServerResponse]:
        assert self._controller is not None
        # Send command to the controller
        if self.exited:
            raise ConnectionError("Debugger has exited")
        log.info("[*] Sending command: %s", cmd)
        return self.raw(json.dumps(cmd))
    
    def raw(self, cmd: str) -> Optional[JDBServerResponse]: 
        try:
            self._controller.sendall(cmd.encode().strip()+b"\n")
            response = self.recv_resp()
        except BrokenPipeError:
            log.warning("[*] Connection closed unexpectedly")
            self.exited = True
            response = None

        return response

    
    def recv_resp(self) -> JDBServerResponse:
        # Receive response from the controller
        log.info("[*] Receiving response")
        data = self._controller.recv(1024).decode()
        if not data:
            raise ConnectionError("Connection closed by the remote debugger")
        log.info("[+] Received response: %s", data)
        while True:
            try:
                parsed = json.loads(data)
                break
            except json.JSONDecodeError:
                log.info("[*] Waiting for more data")
                data += self._controller.recv(1024).decode()
                if not data:
                    raise ConnectionError("Connection closed by the remote debugger")
        resp = JDBServerResponse.from_dict(parsed)
        if resp.status == JDBServerResponseStatus.ERROR:
            log.error("[!] Error in response: %s", resp.data)
        if resp.data == "Server shutting down":
            self._controller.close()
            self.exited = True
        return resp
    
    def load_binary(self):
        # Load the binary in the controller
        log.info("[*] Loading binary: %s", self.binary)
        msg = {"cmd": "load", 
               "classname": self.class_name or self.binary.stem, 
               "classpath": [str(x) for x in self.class_path], 
               "sourcepath": [str(x) for x in self.source_path],
               "args": self.argv}
        return self.send_cmd(msg)
    
    def re_run(self):
        self._debugger_stdout.clear()
        bps = self.breakpoints.copy()
        self.breakpoints.clear()
        self.stdout.clear()
        self.context.reset()
        self.quit(close_controller=True)
        self._init_controller()
        self._exit_code = None
        self._current_thread = None
        self._has_started = False
        self._cmd_ready = False
        self.exited = False

        self._init_controller()
        for bp in bps:
            self.set_breakpoint(class_path=bp.class_name, line=bp.line, function=bp.function)

    def run(self):
        self.re_run()
        if not isinstance(self._controller, socket.socket):
            self.send_cmd({"cmd": "run", "args": self.argv})
        else:
            self.continue_execution()

    def quit(self, close_controller=False):

        if not self.exited:
            self.send_cmd({"cmd": "quit"})
        if close_controller:
            self._disconnect_controller()
        self.exited = True

    def step(self, num=1):
        self.send_cmd({"cmd": "step", "arg": num})

    def next(self, num=1):
        self.send_cmd({"cmd": "next", "arg": num})

    def step_insn(self, num=1):
        raise NotImplementedError("step_insn is not implemented for Java")

    def next_insn(self, num=1):
        raise NotImplementedError("next_insn is not implemented for Java")

    def continue_execution(self, num=1):
        for _ in range(num):
            self.send_cmd({"cmd": "cont"})

    def set_breakpoint(self, class_path: str = None, line: int = None, function: str = None):
        bp = Breakpoint(file=None, addr=None, class_name=class_path, line=line, function=function)
        if class_path is not None and line is not None:
            location = f"{class_path}:{line}"
        elif function is not None and class_path is not None:
            location = f"{class_path}.{function}"
        else:
            raise ValueError("Breakpoint must be set by class and line or function")

        break_cmd = {'cmd': 'set_breakpoint', 'location': location}
        self.send_cmd(break_cmd)
        self.breakpoints.append(bp)
    
    def remove_breakpoint(self, bp: Breakpoint):
        if bp.class_name is not None and bp.line is not None:
            location = f"{bp.class_name}:{bp.line}"
        elif bp.function is not None:
            location = bp.function
        else:
            raise ValueError("Breakpoint must be removed by class and line or function")

        self.send_cmd({"cmd": "remove_breakpoint", "location": location})
        self.breakpoints.remove(bp)

    @property
    def register_info(self) -> Dict[str, int]:
        raise NotImplementedError("register_info is not implemented for Java")

    def update_locals(self):
        local_vars: List[Variable] = []
        resp = self.send_cmd({"cmd": "local_variables"})
        if self.exited:
            return
        _, lvars = resp.data
        for thing in lvars:
            var = Variable(name=thing, value=lvars[thing], type=type(lvars[thing]).__name__)
            local_vars.append(var)
        self.context.locals = local_vars

    def update_backtrace(self):
        bt_lines = []
        resp = self.send_cmd({"cmd": "backtrace"})
        vars = self.send_cmd({"cmd": "local_variables"})
        if self.exited:
            return
        raw_args, _ = vars.data
        args = []
        for thing in raw_args:
            var = Variable(name=thing, value=raw_args[thing], type=type(raw_args[thing]).__name__)
            args.append(var)

        for thing in resp.data:
            depth = thing.get('index', 1)
            method = thing.get('function', "").split(".")[-1]
            class_name = ".".join(thing.get('function', "").split(".")[:-1])
            location = thing.get('location', "")
            if location == "native method":
                file = Path("")
                line_no = -1
            else:
                file, line_no = location.split(":")
                file = Path(file)
            bl = BacktraceLine(
                depth=int(depth), file=file, class_name=class_name, function_name=method, line=int(line_no), instruction=None, args=args if depth == 1 else None,
            )
            bt_lines.append(bl)
        self.context.backtrace.update_bt(bt_lines)

    def update_frame(self):
        if not self.context.backtrace.bt:
            return
        self.context.frame = Frame(
            addr=None,
            function=self.context.backtrace.bt[0].function_name,
            args=self.context.backtrace.bt[0].args,
            file=self.context.backtrace.bt[0].file,
            line=self.context.backtrace.bt[0].line,
            text=None,
        )
