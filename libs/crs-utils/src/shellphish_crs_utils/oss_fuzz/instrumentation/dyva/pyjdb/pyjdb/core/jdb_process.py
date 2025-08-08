import typing as _typ
import sys
import re

import pexpect as _pexpect

from pyjdb.core import helpers as _helpers, exceptions as _exceptions


class JDBProcess():
    """A class to run the JDB process and interact with it
    """
    def __init__(self, target_class_name: str, class_path: list[str] = [], exclude_classes: list[str] = [], source_path: list[str] = None):
        """Initialize the JBDProcess object

        Args:
            target_class_name (str): The target class (most likely inside the harness)
            class_path (list, optional): The path to the necessary dependencies (jar/class files). Defaults to [].
            exclude_classes (list, optional): Any classes to exclude from debugging. Defaults to None.
        """
        self.pty = None
        self.target_class_name = target_class_name
        if isinstance(class_path, str):
            class_path = [class_path]
        self.source_path = source_path
        self.class_path = [_helpers.JAZZER_STANDALONE_JAR] + class_path
        self.entry_method = _helpers.JAZZER_ENTRYPOINT
        self.trace = []
        self.trace_max = 10000
        self.exclude_classes = exclude_classes

    def _build_jdb_cmd(self, args: list[str]) -> str:
        """Build the command used to invoke JDB

        Args:
            args (list[str]) : Any arguments to pass to the target.
            For example the input file. Defaults to [].

        Returns:
            str: The command that can be used to start JDB
        """
        # Example command:
        # jdb \
        # -classpath jazzer_standalone.jar:mock-java.jar:/out \
        # com.code_intelligence.jazzer.Jazzer \
        # --target_class=Harness \
        # /work/pov_input

        cmd = [_helpers.JDB_NAME]

        if self.source_path is not None:
            if not isinstance(self.source_path, list):
                sp = [self.source_path]
            else:
                sp = self.source_path 
            
            if "." not in sp:
                sp = ["."] + sp
            
            cmd += ['-sourcepath', ":".join(sp)]

        cp = self.class_path
        if "." not in cp:
            cp = ["."] + cp

        cmd += ['-classpath', ":".join(cp)]

        cmd += [_helpers.JAZZZER_CLASS_NAME]

        cmd += [f"--target_class={self.target_class_name}"]

        cmd += ["-timeout=86400"]

        assert isinstance(args, list)
        if len(args) > 0:
            cmd += args

        return " ".join(cmd)

    def _reset_trace_history(self):
        self.trace = []

    def _append_trace_history(self, info: _typ.Mapping) -> _typ.Mapping:
        # Add the info to the list
        self.trace.append(info)

        # Cull the excess frames
        if self.trace_max is not None and self.trace_max > 0:
            if len(self.trace) > self.trace_max:
                self.trace = self.trace[-self.trace_max:]

        return info
    
    def _flush_command_from_buffer(self):
        self.pty.expect("\r\n")

    def _recv_until_next_prompt(self) -> str:
        self._flush_command_from_buffer()
        if idx := self.pty.expect([_helpers.REGEXP_PROMPT, _pexpect.EOF, _pexpect.TIMEOUT]) > 0:
            assert idx != 1, f"Unexpected EOF: {self.pty.before}"
            assert idx != 2, f"Unexpected TIMEOUT: {self.pty.before}"
        return self.pty.before
    
    def _up(self):
        self.pty.sendline("up")
        self._recv_until_next_prompt()

    def _down(self):
        self.pty.sendline("down")
        self._recv_until_next_prompt()

    def _step_up(self):
        self.pty.sendline("step up")
        self._recv_until_next_prompt()

    def _cont(self):
        self.pty.sendline("cont")
        self._recv_until_next_prompt()

    def _set_breakpoint(self, location: str):
        self.pty.sendline(f"stop at {location}")
        self._recv_until_next_prompt()

    def _remove_breakpoint(self, location: str):
        self.pty.sendline(f"clear {location}")
        self._recv_until_next_prompt()

    def _backtrace(self) -> list[str]:
        self.pty.sendline("where")
        return _helpers.parse_jdb_backtrace(self._recv_until_next_prompt())

    def _step(self) -> dict:
        """_summary_

        Raises:
            JdbHostErrorException
            JdbException
            JdbHostExitedException

        Returns:
            dict: _description_
        """
        if not self.active:
            return None

        # Make a step
        self.pty.sendline("step")

        # Collect location
        try:
            self.pty.expect(_helpers.REGEXP_PATT_STEP_EXPECT)
        except _pexpect.EOF as e:
            e.__class__ = _exceptions.JdbHostExitedException
            raise e
        except _pexpect.TIMEOUT as e:
            e.__class__ = _exceptions.JdbException
            raise e

        if info:= _helpers.parse_jdb_step(self.pty.after) is None:
            raise _exceptions.JdbHostErrorException(f"Unexpected error: '{self.pty.after}'")

        # Add to record
        return self._append_trace_history(info)

    def _next(self) -> dict:
        if not self.active:
            return None

        # Make a step
        self.pty.sendline("next")

        # Collect location
        try:
            self.pty.expect(_helpers.REGEXP_PATT_STEP_EXPECT)
        except _pexpect.EOF as e:
            e.__class__ = _exceptions.JdbHostExitedException
            raise e
        except _pexpect.TIMEOUT as e:
            e.__class__ = _exceptions.JdbException
            raise e

        if info:= _helpers.parse_jdb_step(self.pty.after) is None:
            raise _exceptions.JdbHostErrorException(f"Unexpected error: '{self.pty.after}'")

        # Add to record
        return self._append_trace_history(info)

    def _locals(self) -> dict:
        if not self.active:
            return None

        # Print out all local variables
        self.pty.sendline("locals")

        # Expect the variables from method arguments (or a message that we don't have
        # debug information for this frame).
        self.pty.expect(
            "(No local variables[^\r\n]*|.*ocal variable "
            "information not available[^\r\n]*|Method arguments:)")

        # If there is debug information, which we detect by the presence of the message
        # "Method", then also look for local variables.
        if "Method" in self.pty.after:
            self.pty.expect("Local variables:")

        raw_str_args = self.pty.before

        # Seek forward to prompt
        if idx := self.pty.expect([_helpers.REGEXP_PROMPT, _pexpect.EOF, _pexpect.TIMEOUT]) > 0:
            assert idx != 1, f"Unexpected EOF: {self.pty.before}"
            assert idx != 2, f"Unexpected TIMEOUT: {self.pty.before}"

        raw_str_locals = self.pty.after

        # Parse the strings
        args = _helpers.parse_jdb_values(raw_str_args)
        local = _helpers.parse_jdb_values(raw_str_locals)

        return args, local

    @property
    def active(self) -> bool:
        """
        Provides whether the `JDBProcess` is active. If it is not, it must be
        reset using the `spawn` method.

        :return: A `Boolean` representing the status of the `JDBProcess`.
        """

        return not (self.pty is None or self.pty.closed or self.pty.eof())

    def start_jdb(self, args: list[str] = None):
        """Start the JDB process

        Args:
            args (list[str], optional): Any additional arguments to the target. Defaults to [].
        """

        # In case we have a live process going: Terminate it
        self.close()

        # Launch the class through JDB
        cmd = self._build_jdb_cmd(args=args if args else [])
        print(f"Starting JDB with command: {cmd}")
        # self.pty = _pexpect.spawnu(cmd)
        self.pty = _pexpect.spawnu(cmd, logfile=sys.stdout)

        self.pty.sendline(f"stop in {self.target_class_name}.{self.entry_method}")

        self.pty.expect(".*Deferring breakpoint.*")
        self.pty.sendline("run")
        self.pty.expect(".*Breakpoint hit:")

        # Activate precise tracing information:
        # - exclude standard library from events
        exclude_list = _helpers.JDB_DEFAULT_EXCLUDED
        if self.exclude_classes is not None:
            exclude_list = exclude_list + self.exclude_classes
        self.pty.sendline(f"exclude {','.join(exclude_list)}")
        # - provide information on methods being entered, exited (and return value)
        # self.pty.sendline("trace methods 1")

        # Run dummy method to clear
        self._locals()

        # Reset trace
        self._reset_trace_history()
        self._remove_breakpoint(f"{self.target_class_name}.{self.entry_method}")

    def close(self):
        """Close the PTY
        """
        if self.pty is not None:
            # noinspection PyBroadException
            try:
                self.pty.close()
            except Exception:
                pass

    def run(self):
        """Run the target program
        """
        self.pty.sendline("run")

    def step(self, num: int = 1):
        """Step into lines

        Args:
            num (int, optional): Number of lines to step. Defaults to 1.
        """
        for _ in range(num):
            self._step()

    def next(self, num: int = 1):
        """Step over lines

        Args:
            num (int, optional): Number of lines to step. Defaults to 1.
        """
        for _ in range(num):
            self._next()

    def up(self, num: int = 1):
        """Step up the stack

        Args:
            num (int, optional): Number of lines to step. Defaults to 1.
        """
        for _ in range(num):
            self._up()

    def down(self, num: int = 1):
        """Step down the stack

        Args:
            num (int, optional): Number of lines to step. Defaults to 1.
        """
        for _ in range(num):
            self._down()

    def finish(self):
        """Continue until the current method returns
        """
        self._step_up()

    def cont(self):
        """Continue execution until the next breakpoint
        """
        self._cont()

    def program_counter(self):
        """Get the PC

        Raises:
            NotImplementedError: Not implemented yet
        """
        raise NotImplementedError("Not implemented yet")

    def set_breakpoint(self, location: str):
        """Set a breakpoint at the given location

        Args:
            location (str): <class_id>:<line_number> or <class_id>:<method_name>
        """
        self._set_breakpoint(location)

    def remove_breakpoint(self, location: str):
        """Remove a breakpoint

        Args:
            location (str): Similar to set_breakpoint
        """
        self._remove_breakpoint(location)

    def local_variables(self) -> tuple[dict, dict]:
        """Get the local variables of the current frame

        Returns:
            dict: A dictionary containing the local variables
        """
        return self._locals()

    def backtrace(self) -> list[str]:
        """Return the current backtrace

        Returns:
            list[str]: A list of strings representing the backtrace
        """
        return self._backtrace()

    def raw(self, msg: str):
        """Send a raw command to the JDB process

        Args:
            msg (str): The command to send to JDB
        """
        self.pty.sendline(msg)

    def quit(self):
        """Quit the JDB process
        """
        self.pty.sendline("quit")
        self.close()

    def dump(self, obj: str) -> _typ.Optional[str]:
        if not self.active:
            return None

        # First get a prompt
        self.pty.sendline("")
        self.pty.expect(r".*\[.*\] ")
        rawstr_prompt = self.pty.after.strip()

        # Escape prompt
        esc_prompt = rawstr_prompt
        esc_prompt = esc_prompt.replace("[", r"\[")
        esc_prompt = esc_prompt.replace("]", r"\]")

        # Send command
        self.pty.sendline(f"dump {obj}")

        # Expect output
        pattern = f"{obj} = .*{esc_prompt}"
        self.pty.expect(pattern)

        # Parse output
        ret = self.pty.after

        # - remove last line break and prompt that follows
        last_line_break = ret.rfind("\n")
        ret = ret[:last_line_break].strip()

        # - remove obj name and equal sign
        ret = ret.replace("{obj} =", "").strip()

        # Parse the value
        parsed_ret = _helpers.parse_jdb_value(ret)

        return parsed_ret
