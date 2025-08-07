## Harness using gdb server

import tempfile
import re
import logging

from typing import Dict, List, Any
from pathlib import Path
from collections import Counter

from pygdbmi.gdbcontroller import GdbController

from universal_dbg.debuggers.debugger import Debugger
from universal_dbg.debuggers.context import Backtrace, Variable, BacktraceLine, Frame

log = logging.getLogger("gdb")
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)

bt_regex = re.compile(r"#(\d+)\s+(0x[0-9a-f]+)*\s+(?:in\s+)*(\S+).*?(?:.*at\s)*(?:(\S+):(\d+))?")

class GDBDebugger(Debugger):
    
    def __init__(self, *args, **kwargs):
        remote = kwargs.pop("remote", None)
        extra_args = kwargs.pop("extra_args", None)
        super().__init__(*args, **kwargs)
        self._controller = self._get_controller(extra_args)
        self._set_remote(remote)
        file_res = self._controller.write(f"file {self.program}")
        self._has_debug = any("No debugging symbols found" not in x["payload"] for x in file_res if x["type"] == "console")
        self._exit_code = None
        self.tempfile = tempfile.NamedTemporaryFile()
        self._gdb_messages = None

    def _get_controller(self, extra_args=None):
        # Connect to the GDB server running on the UNIX domain socket
        if extra_args:
            return GdbController()
        else:
            return GdbController(command=extra_args)
    
    def _set_remote(self, remote):
        if remote is None:
            return
        print(f"SETTING REMOTE {remote}")
        self._controller.write(f"target remote {remote}") 
    
    # def _set_remote(self, remote):
    #     if remote is None:
    #         return
    #     print(f"SETTING REMOTE {remote}")
    #     self._controller.write(f"target remote {remote}")
    
    # def _run(self, *args, **kwargs):
    #     run_args = ' '.join(args) + ' ' + ' '.join([f'--{k}={v}' for k, v in kwargs.items()])
    #     if self.stdin is not None:
    #         with open(self.tempfile.name, 'wb') as f:
    #             f.write(self.stdin)
    #         run_args += f" < {self.tempfile.name}"
    #     elif self.argv:
    #         run_args += " " + " ".join(self.argv)

    #     log.info("RUNNING: %s", run_args)
    #     run_output = self._controller.write(f"run {run_args}")
    #     log.info("GDB OUTPUT: %s", run_output)
    #     self._gdb_messages = run_output
    #     return run_output

    def _run(self, *args, **kwargs):
        
        run_args = ' '.join(args) + ' ' + ' '.join([f'--{k}={v}' for k, v in kwargs.items()])
        print("run_args: ", run_args)
        if self.stdin is not None:
            with open(self.tempfile.name, 'wb') as f:
                f.write(self.stdin)
            run_args += f" < {self.tempfile.name}"
        elif self.argv:
            run_args += " " + " ".join(self.argv)
        
        log.info("RUNNING: %s", run_args)
        self._controller.write(f"set args {run_args}")
        run_output = self._controller.write("run")
        # run_output = self._controller.write(f"run {run_args}")
        log.info("GDB OUTPUT: %s", run_output)
        self._gdb_messages = run_output
        return run_output
    
    def _set_breakpoint(self, location: str | int):
        if isinstance(location, int): # Address
            return self._controller.write(f"break *{hex(location)}")
        else: # Function name
            return self._controller.write(f"break {location}")
    
    def _continue_execution(self, num=1):
        cont_info = self._controller.write(f"continue {num}")
        self._gdb_messages = cont_info
        return cont_info

    def _finish(self):
        self._controller.write("finish")
    
    def _step(self, num=1):
        if not self._has_debug:
            return self._step_insn(num)
        
        step_info = self._controller.write(f"step {num}")
        self._gdb_messages = step_info
        return step_info
    
    def _next(self, num=1):
        if not self._has_debug:
            return self._next_insn(num)

        next_info = self._controller.write(f"next {num}")
        self._gdb_messages = next_info
    
    def _step_insn(self, num=1):
        step_info = self._controller.write(f"stepi {num}")
        self._gdb_messages = step_info
    
    def _next_insn(self, num=1):
        next_info = self._controller.write(f"nexti {num}")
        self._gdb_messages = next_info
    
    def _program_counter(self) -> int:
        pc_info = self._controller.write(f"x/i $pc")
        for message in pc_info:
            if message["payload"] is None:
                continue
            if message["payload"].startswith("=>"):
                return int(message["payload"].split(" ")[1], 16)

    def _get_breakpoint_info(self) -> List[int]:
        breakpoint_info = self._controller.write(f"info breakpoints")
        breakpoints = set()
        for message in breakpoint_info:
            if message["payload"] is None:
                continue
            breakpoint_addr = re.search(r".*(0x([a-f0-9])+)", message["payload"])
            if breakpoint_addr is not None:
                breakpoints.add(int(breakpoint_addr.group(1), 16))
        return list(breakpoints)
    
    @property
    def register_info(self) -> Dict[str, int]:
        reg_info = {}
        for reg in self._controller.write("info registers"):
            if reg["type"] == "console":
                reg_name, reg_val = re.search(r"(\w+\d*)\s*(0x[a-f0-9]+)", reg["payload"]).groups()
                reg_info[reg_name] = int(reg_val, 16)
        return reg_info
    
    def update_locals(self):
        local_vars: List[Variable] = []
        for line in self._controller.write("info locals"):
            log.debug("LINE:%s", line)
            if line["type"] == "result" and line["message"] == "error":
                self.exited = True
                break
            if line["type"] != "console":
                continue
            if "No symbol table info available" in line["payload"]:
                continue
            if line["payload"] == "No locals.\n":
                break

            var = self._get_var_info(line)
            if var is None:
                continue
            local_vars.append(var)

        self.context.update_locals(local_vars)
    
    def _get_var_info(self, gdb_message: Any, given_name: str = None) -> Variable:
        var_line = gdb_message["payload"].strip()
        var_split = var_line.find(' = ')
        var_name = var_line[:var_split]
        var_val = var_line[var_split+3:]
        out = self._controller.write(f"whatis {var_name}")[1]["payload"]
        if not isinstance(out, str):
            return None
        print("before out")
        
        var_type = out.split("=")[-1].strip()
        if "char" in var_type and (('[' in Counter(var_type) and Counter(var_type)['['] == 1) or "*" == var_type.replace('char', '').strip()):
            line = self._controller.write(f"x/s {var_name}")[1]["payload"].strip()
            quote = line.find('"')
            var_val = line[max(quote, 0):]
        return Variable(name=given_name or var_name, value=var_val, type=var_type)
    
    def _update_globals(self):
        global_vars = []
        for global_name in self.context.get_globals():
            messages = self._controller.write(f"p {global_name}")
            log.debug("%s", messages)
            if any(message["message"] == "error" for message in messages):
                continue
            var = self._get_var_info(messages[1], global_name)
            if var is None:
                continue
            global_vars.append(var)
        self.context.update_globals(global_vars)

         
    def update_context(self):
        super().update_context()
        self._update_globals()
    
    def update_backtrace(self):
        global bt_regex
        
        bt = [x["payload"].strip() for x in self._controller.write("backtrace") if x["type"] == "console"]
        bt_lines: List[BacktraceLine] = []
        for line in bt:
            if 'Backtrace stopped' in line:
                continue
            bt_parsed = re.search(bt_regex, line)
            if bt_parsed is None:
                continue
            idx, addr, func, file, lineno = bt_parsed.groups()
            bt_line = BacktraceLine(depth=idx, file=Path(file or ""), class_name="", function_name=func, line=int(lineno or -1), instruction=int(addr or "-1", 16))
            bt_lines.append(bt_line)
        self.context.update_backtrace(bt_lines)
        self.context.backtrace._raw = "\n".join([str(i) for i in bt_lines])
 
    def quit(self):
        self.tempfile.close()
        self._controller.exit()
    
    def update_frame(self):
        line_text: str = ""
        for message in self._gdb_messages:
            if message["type"] == "console" and message["message"] is None:
                line_text = message["payload"].strip()
                if "The program no longer exists." in line_text:
                    self.exited = True
            
            if message["type"] == "output" and message["message"] is None:
                self.stdout.append(message["payload"])
            if message["type"] != "notify":
                continue
            if "frame" not in message["payload"]:
                continue
            addr = int(message["payload"]["frame"]["addr"], 16)
            function = message["payload"]["frame"]["func"]
            args = [Variable(name=x["name"], value=x["value"], type=None) for x in message["payload"]["frame"]["args"]]
            file = message["payload"]["frame"].get("fullname", "")
            line = int(message["payload"]["frame"].get("line", -1))
            text = line_text
            self.context.frame = Frame(addr=addr, function=function, args=args, file=Path(file), line=line, text=text)
    
    def raw(self, cmd: str) -> Any:
        return self._controller.write(cmd)