import tempfile
import re
import logging
import time

from typing import List, Any
from pathlib import Path
from collections import Counter

from pygdbmi.gdbcontroller import GdbController
from pygdbmi.IoManager import GdbTimeoutError

from debug_lib.debuggers.debugger import Debugger
from debug_lib.debuggers.context import Variable, BacktraceLine, Frame, Breakpoint, Register
from functools import wraps

log = logging.getLogger("gdb")
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)

bt_regex = re.compile(r"#(\d+)\s+(0x[0-9a-f]+)*\s+(?:in\s+)*(\S+).*?(?:.*at\s)*(?:(\S+):(\d+))?")

CURRENT_DIR = Path(__file__).absolute().parent
GDB_SCRIPTS = CURRENT_DIR / "gdb_scripts"

def gdb_messages(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            self._gdb_messages += self._controller.get_gdb_response()
        except GdbTimeoutError:
            pass
        except OSError:
            return None
        out = func(self, *args, **kwargs)
        self._gdb_messages += out
        return out

    return wrapper


class GDBDebugger(Debugger):
    def __init__(self, *args, **kwargs):
        self.remote = kwargs.pop("remote", None)
        extra_args = kwargs.pop("extra_args", None)
        self.tempfile = tempfile.NamedTemporaryFile()
        self._gdb_messages = []
        super().__init__(*args, **kwargs)

        # Return the gdb client that will connect to the gdb server
        self._controller = self._get_controller(extra_args)
        # Set the remote debugging through the UNIX domain socket
        if self.remote is not None:
            self._set_remote()
        # Set the program as the executable to debug
        file_res = self.raw(f"file {self.program}")

        self._has_debug = any(
            "No debugging symbols found" not in x["payload"] for x in file_res if x["type"] == "console"
        )
        self._gdb_messages.clear()
        self._exit_code = None
        self.raw(f"source {GDB_SCRIPTS / 'rca_tools.py'}")

    def _get_controller(self, extra_args=None):
        # Get a gdb client
        return GdbController(command=extra_args)

    def _wait_for_completion(self):
        num_attempts = 10
        while True:
            try:
                for response in self._gdb_messages:
                    if response["type"] == "result" and response["message"] == "done":
                        return

                self._gdb_messages += self._controller.get_gdb_response(timeout_sec=5)
            except Exception:
                num_attempts -= 1
                if num_attempts == 0:
                    log.error("GDB server did not respond")
                    raise Exception("GDB server did not respond")

            log.debug(" 🥱 Waiting for response from gdbserver")
            time.sleep(1)

    def _set_remote(self):
        # Connect to the GDB server running on the UNIX domain socket
        if self.remote is None:
            return
        log.debug("SETTING REMOTE %s", self.remote)

        # Attach to gdb server running on the UNIX domain socket

        # We need to wait until we have a connection and
        # the remote ended reading the symbols!

        remote_cmd = f"target extended-remote {self.remote}"
        self.raw(remote_cmd)

        # If the connection is not established, we need to exit and reconnect
        self._wait_for_completion()

        # I DON'T THINK WE NEED THESE
        # self.raw(f"set remote exec-file {self.program}")
        # self._wait_for_completion(cmd=f"set remote exec-file {self.program}", redo_cmd=True)

        log.debug("REMOTE SET SUCCESSFULLY ✅")

    @gdb_messages
    def run(self):
        self.context.reset()
        if self.argv:
            run_args = " " + " ".join(self.argv)
            self.raw(f"set args {run_args}")

        if self.stdin is not None:
            with open(self.tempfile.name, "wb") as f:
                f.write(self.stdin)
            run_output = self.raw(f"run < {self.tempfile.name}")
        else:
            run_output = self.raw("run")

        return run_output

    def set_breakpoint(
        self, file: str = None, line: int = None, function: str = None, address: int = None
    ) -> Breakpoint:
        if file and line:
            output = self.raw(f"break {file}:{line}")
        elif function:
            output = self.raw(f"break {function}")
        else:
            output = self.raw(f"break *{hex(address)}")
        for message in output:
            if message["message"] != "breakpoint-created":
                continue
            bp_dict = message["payload"]["bkpt"]
            new_bp = Breakpoint(
                file=bp_dict.get("file"),
                line=bp_dict.get("line"),
                addr=int(bp_dict.get("addr"), 16) if bp_dict.get("addr") != "<PENDING>" else None,
                function=bp_dict.get("func"),
                id=bp_dict.get("number"),
            )
            self.breakpoints.append(new_bp)
            break

    def remove_breakpoint(self, bp: Breakpoint):
        assert bp.id is not None and bp in self.breakpoints
        self.raw(f"delete {bp.id}")
        self.breakpoints.remove(bp)

    @gdb_messages
    def continue_execution(self, num=1):
        cont_info = self.raw(f"continue {num}")
        if not any(message["type"] == "error" for message in cont_info):
            self.context.frame.depth = 0
        return cont_info

    @gdb_messages
    def finish(self):
        output = self.raw("finish")
        if not any(message["type"] == "error" for message in output):
            self.context.frame.depth = 0
        return output

    @gdb_messages
    def step(self, num=1):
        if not self._has_debug:
            return self.step_insn(num)

        step_info = self.raw(f"step {num}")
        if not any(message["type"] == "error" for message in step_info):
            self.context.frame.depth = 0
        return step_info

    @gdb_messages
    def next(self, num=1):
        if not self._has_debug:
            return self.next_insn(num)

        next_info = self.raw(f"next {num}")
        if not any(message["type"] == "error" for message in next_info):
            self.context.frame.depth = 0
        return next_info

    @gdb_messages
    def step_insn(self, num=1):
        step_info = self.raw(f"stepi {num}")
        return step_info

    @gdb_messages
    def next_insn(self, num=1):
        next_info = self.raw(f"nexti {num}")
        return next_info

    @gdb_messages
    def up(self, num=1):
        up_info = self.raw(f"up {num}")
        if not any(message["type"] == "error" for message in up_info):
            self.context.frame.depth += 1
        return up_info

    @gdb_messages
    def down(self, num=1):
        down_info = self.raw(f"down {num}")
        if not any(message["type"] == "error" for message in down_info):
            self.context.frame.depth -= 1
        return down_info

    def program_counter(self) -> int:
        pc_info = self.raw("x/i $pc")
        for message in pc_info:
            if message["payload"] is None:
                continue
            if isinstance(message["payload"], str) and message["payload"].startswith("=>"):
                try:
                    return int(message["payload"].split(" ")[1].split(":")[0], 16)
                except ValueError:
                    log.error("Error parsing program counter: %s", message["payload"])
                    continue

    def _update_registers(self):
        regs = {}
        for reg in self.raw("info registers"):
            if reg["type"] == "console":
                reg_name, reg_val = re.search(r"(\w+\d*)\s*(0x[a-f0-9]+)", reg["payload"]).groups()
                if reg_name not in self.context.registers:
                    regs[reg_name] = Register(name=reg_name, value=int(reg_val, 16), changed=True)
                elif self.context.registers[reg_name].value != int(reg_val, 16):
                    regs[reg_name] = Register(name=reg_name, value=int(reg_val, 16), changed=True)
                else:
                    self.context.registers[reg_name].changed = False
        self.context.pc = self.program_counter()
        self.context.update_registers(regs)

    def update_locals(self):
        local_vars: List[Variable] = []
        locals_info = self.raw("info locals")
        idx = 0
        # Skip to the first log line where our command was executed
        for idx, line in enumerate(locals_info):
            if line["type"] == "log" and line["payload"] == "info locals\n":
                break

        locals_info = locals_info[idx:]

        for line in locals_info:
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
        var_split = var_line.find(" = ")
        var_name = var_line[:var_split]
        var_val = var_line[var_split + 3 :]
        out = self.raw(f"whatis {var_name}")[1]["payload"]
        if not isinstance(out, str):
            return None

        var_type = out.split("=")[-1].strip()
        if "char" in var_type and (
            ("[" in Counter(var_type) and Counter(var_type)["["] == 1) or "*" == var_type.replace("char", "").strip()
        ):
            line = self.raw(f"x/s {var_name}")[1]["payload"].strip()
            quote = line.find('"')
            var_val = line[max(quote, 0) :]
        elif "*" in var_type:
            line = self.raw(f"p {'*' * var_type.count('*')}{var_name}")[1]["payload"]
            var_val = line[line.find("=") + 1 :].strip()
        return Variable(name=given_name or var_name, value=var_val, type=var_type)

    def _update_globals(self):
        global_vars = []
        for global_name in self.context.get_globals():
            messages = self.raw(f"p {global_name}")
            log.debug("%s", messages)
            if any(message["message"] == "error" for message in messages):
                continue
            var = self._get_var_info(messages[1], global_name)
            if var is None:
                continue
            global_vars.append(var)
        self.context.update_globals(global_vars)

    def update_context(self):
        self._update_stdout()
        super().update_context()
        self._update_globals()
        self._update_registers()

    def _update_stdout(self):
        for message in self._gdb_messages:
            if message["type"] == "output" and message["message"] is None:
                self.stdout.append(message["payload"])

    def update_backtrace(self):
        global bt_regex

        bt = [
            x["payload"].strip()
            for x in self.raw("backtrace")
            if x["type"] == "console" and x["payload"].startswith("#")
        ]
        if not bt:
            bt = [x["payload"].strip() for x in self.raw("backtrace") if x["type"] == "console"]
        bt_lines: List[BacktraceLine] = []
        for line in bt:
            if "Backtrace stopped" in line:
                continue
            bt_parsed = re.search(bt_regex, line)
            if bt_parsed is None:
                continue
            idx, addr, func, file, lineno = bt_parsed.groups()
            bt_line = BacktraceLine(
                depth=idx,
                file=Path(file or ""),
                class_name="",
                function_name=func,
                line=int(lineno or -1),
                instruction=int(addr or "-1", 16),
            )
            bt_lines.append(bt_line)
        self.context.update_backtrace(bt_lines)
        self.context.backtrace._raw = "\n".join([str(i) for i in bt_lines])

    def quit(self):
        if self.remote is not None:
            try:
                self.raw("monitor exit")
            except Exception as e:
                log.error("Error exiting gdbserver: %s", e, exc_info=True)
        self.tempfile.close()
        self._controller.exit()

    def update_frame(self):
        line_text: str = ""
        for message in self._gdb_messages:
            if message["type"] == "console" and message["message"] is None:
                line_text = message["payload"].strip()
                if "The program no longer exists." in line_text:
                    self.exited = True
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
            self.context.frame = Frame(
                addr=addr,
                function=function,
                args=args,
                file=Path(file),
                line=line,
                text=text,
                depth=self.context.frame.depth,
            )

    @gdb_messages
    def raw(self, cmd: str) -> Any:
        # log.debug("RAW CMD: %s", cmd)
        output = self._controller.write(cmd, timeout_sec=5)
        # log.debug("RAW OUTPUT: %s", pprint.pformat(output, indent=2))
        return output
