import tempfile
import io
import os
import re
import json
import subprocess
import select
import time
import logging

from pathlib import Path
from tracemalloc import start
from typing import Optional, Dict, List, Tuple

from universal_dbg.debuggers.debugger import Debugger
from universal_dbg.debuggers.context import BacktraceLine, Variable, Frame

log = logging.getLogger("jdb")
log.setLevel(logging.INFO)

def consume_stdout(func):
    def wrapper(self, *args, **kwargs):
        prev_line = len(self._debugger_stdout)
        self.safe_get_file_obj_output(self._controller.stdout)
        self.stdout.extend(self._debugger_stdout[prev_line:])
        if self.exited:
            return
        result = func(self, *args, **kwargs)
        self.safe_get_file_obj_output(self._controller.stdout)
        started_stdout = False
        # for line in self._prog_stdout[prev_line:]:
            # if line.startswith("> "):
                # started_stdout = True
                # line = line[2:]
            # if not started_stdout:
                # continue
            # self.stdout.append(line)
            # if line.startswith("Step completed: \""):
                # break
        return result
    return wrapper

class JavaDebugger(Debugger):
    def __init__(self, debug_class, class_path: str=None, source_path: str=None, **kwargs):
        super().__init__(debug_class, **kwargs)
        self.debug_class = debug_class
        self.tempfile = tempfile.NamedTemporaryFile()
        self._source_path = source_path
        self._class_path = class_path
        self._controller: subprocess.Popen
        self._exit_code: int
        self.current_context = None
        self._debugger_stdout: List[str] = []
        self._init_controller()

    def _init_controller(self):
        cmd = ["jdb", "-classpath", self._class_path, "-sourcepath", self._source_path, self.debug_class, *self.argv]
        log.info("Starting JDB:\n%s", " ".join(str(x) for x in cmd))
        self._controller = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run(self, *args, **kwargs):
        self._send_cmd(f"run")
    
    @consume_stdout
    def _send_cmd(self, cmd: str):
        log.debug("Sending command: %s", cmd)
        self._controller.stdin.write(cmd + '\n')
        self._controller.stdin.flush()
    
    def _continue_execution(self, num=1):
        for _ in range(num):
            self._send_cmd("cont")
    
    def _step(self, num=1):
        for _ in range(num):
            self._send_cmd("step into")
    
    def _set_breakpoint(self, location: str | int):
        if isinstance(location, int):
            log.error("Address breakpoints are not supported")
            return
        stop_type = "at" if len(location.split(":")) == 2 and location.split(":")[1].isdigit() else "in"
        break_cmd = f"stop {stop_type} {location}"
        self._send_cmd(break_cmd)
    
    def _next(self, num=1):
        for _ in range(num):
            self._send_cmd("step over")
    
    def _step_insn(self, num=1):
        self._step()
    
    def _next_insn(self, num=1):
        self._next()

    def safe_get_file_obj_output(self, std_file: io.TextIOWrapper):
        output = []
        empty_count = 0
        current_line = ""
        while empty_count < 10:
            if self._controller.poll() is not None:
                self.exited = True
                break
            r, w, e = select.select([std_file], [], [], 0)
            if std_file in r:
                c = os.read(std_file.fileno(), 1).decode("latin-1")
                if c == '\n':
                    if current_line.split(" ")[0].isdigit():
                        self.context.frame.text = current_line
                    output.append(current_line)
                    current_line = ""
                else:
                    current_line += c
                empty_count = 0
            else:
                empty_count += 1
                time.sleep(0.001)
        if current_line != "":
            self._debugger_stdout.append(current_line)
        self._debugger_stdout.extend(output)
        log.debug('\n'.join(output))
        return output
    
    @property
    def register_info(self) -> Dict[str, int]:
        return {}
    
    def _parse_var_line(self, line: str) -> Variable:
        name, value = line.split(" = ")
        var_type = None
        if value.startswith("instance of "):
            var_type = value[len("instance of "):value.rfind("(")]
        elif value.startswith('"'):
            var_type = "String"
        elif str(int(value)) == value.strip():
            var_type = "int"
        elif "." in value:
            var_type = "float"
        else:
            var_type = None

        start = len(self._debugger_stdout)
        self._send_cmd(f"dump {name}")
        variable_dump = ''.join(self._debugger_stdout[start:])
        variable_dump = variable_dump[variable_dump.find("= ") + 2:]
        var = Variable(name=name, value=variable_dump, type=var_type)
        return var

    def update_locals(self):
        local_vars = []
        self._send_cmd("locals")
        len_stdout = len(self._debugger_stdout)
        try:
            method_start = next(idx for idx, line in enumerate(self._debugger_stdout[::-1]) if "Method arguments:" in line)
        except StopIteration:
            return

        local = False
        for line in self._debugger_stdout[len_stdout - method_start:len_stdout]:
            if line.startswith("Local variables"):
                local = True
                continue
            if "=" not in line:
                break
            var = self._parse_var_line(line)
            if not local:
                self.context.frame.args.append(var)
            else:
                local_vars.append(var)
        self.context.locals = local_vars
    
    def update_backtrace(self):
        bt_lines = []
        start = len(self._debugger_stdout)
        self._send_cmd("where")
        for line in self._debugger_stdout[start:]:
            line = line.strip()
            if not line.startswith("["):
                continue

            line_split = line.split(" ")
            idx = line_split[0]
            method = line_split[1]
            location = line_split[2]
            idx = int(idx[1:-1])
            if len(location.split(":")) == 2:
                file, line = location.split(':')
                file = Path(file[1:])
                if "," in line:
                    line = line.split(",")[0]
                else:
                    line = line[:-1]
                line = int(line)
            else:
                file = Path("")
                line = -1
            class_name = '.'.join(method.split(".")[:-1])
            method = method.split(".")[-1]
            bl = BacktraceLine(depth=idx, file=file, class_name=class_name, function_name=method, line=line, instruction=None)
            bt_lines.append(bl)
        self.context.backtrace.update_bt(bt_lines)
    
    def update_frame(self):
        if not self.context.backtrace.bt:
            return
        self.context.frame = Frame(addr=None, 
                                   function=self.context.backtrace.bt[0].function_name, 
                                   args=[], 
                                   file=self.context.backtrace.bt[0].file, 
                                   line=self.context.backtrace.bt[0].line, 
                                   text=None)
    
    def quit(self):
        if self.tempfile is not None:
            self.tempfile.close()
        if self._controller is not None:
            self._controller.kill()