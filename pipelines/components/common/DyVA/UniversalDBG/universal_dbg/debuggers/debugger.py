import logging

from pathlib import Path
from tabnanny import check
from typing import Union, Dict, List, Tuple, List, Any

from universal_dbg.debuggers.context import DebugContext, Variable

log = logging.getLogger(__name__)

def check_exited(func):
    def wrapper(self, *args, **kwargs):
        if self.exited:
            return
        return func(self, *args, **kwargs)
    return wrapper

def update_context(func):
    def wrapper(self, *args, **kwargs):
        result = func(self, *args, **kwargs)
        if not self.exited:
            self.update_context()
        return result
    return wrapper
 
class Debugger:

    def __init__(self, program: Path, argv: List[str] = None, stdin: bytes = None):
        self.program = program
        self.argv = argv
        self.stdin = stdin
        self.stdout: List[str] = []
        self.context = DebugContext()
        self.exited = False

    @update_context
    def run(self, *args, **kwargs):
        self._run(*args, **kwargs)
    
    def _run(self, *args, **kwargs):
        raise NotImplementedError("Subclasses must implement this method")
    
    def quit(self):
        raise NotImplementedError("Subclasses must implement this method")

    @check_exited
    @update_context
    def step(self, num=1):
        self._step(num)
    
    def _step(self, num=1):
        raise NotImplementedError("Subclasses must implement this method")

    @check_exited
    @update_context
    def step_insn(self, num=1):
        self._step_insn(num)
    
    def _step_insn(self, num=1):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    @update_context
    def next(self, num=1):
        self._next(num)
    
    def _next(self, num=1):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    @update_context
    def next_insn(self, num=1):
        self._next_insn(num)
    
    def _next_insn(self, num=1):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    @update_context
    def up(self):
        self._up()
    
    def _up(self):
        raise NotImplementedError("Subclasses must implement this method")

    @check_exited
    @update_context
    def down(self):
        self._down()
    
    def _down(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    @update_context
    def finish(self):
        self._finish()
    
    def _finish(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    @update_context
    def continue_execution(self):
        return self._continue_execution()
    
    def _continue_execution(self):
        raise NotImplementedError("Subclasses must implement this method")

    @check_exited
    def program_counter(self) -> int:
        return self._program_counter()
    
    def _program_counter(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    @check_exited
    def get_breakpoint_info(self) -> List[int]:
        return self._get_breakpoint_info()
    
    def _get_breakpoint_info():
        raise NotImplementedError("Subclasses must implement this method")

    @check_exited
    def set_breakpoint(self, location: Union[str, int]):
        """_summary_

        Args:
            location (Union[str, int]): Can be either a function name, or an address
        """
        return self._set_breakpoint(location)

    def _set_breakpoint(self, location: Union[str, int]):
        raise NotImplementedError("Subclasses must implement this method")
     
    @property
    def register_info(self) -> Dict[str, int]:
        raise NotImplementedError("Subclasses must implement this method")
    
    @property
    def locals(self) -> List[Variable]:
        """_summary_

        Returns:
            List[LocalVariable]: Returns a list of LocalVariable containing variable name, type, and value
        """
        return self.context.locals
    
    @property
    def globals(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_stack(self, size=0x10):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def backtrace(self):
        return self.context.backtrace
    
    def update_context(self):
        self.update_backtrace()
        self.update_frame()
        self.update_locals()
    
    def update_frame(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def update_backtrace(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def update_locals(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def track_global(self, global_variable_name):
        """
        Add global variable to Debugger Context Tracking
        """
        self.context.track_global(global_variable_name)

    def untrack_global(self, global_variable_name):
        """
        remove global variable from Debugger Context Tracking
        """
        self.context.untrack_global(global_variable_name)

    def raw(self, cmd) -> Any:
        """
        This function passes the command to the underlying debugging engine for advanced usage
        cmd: 
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def print_context(self):
        if self.exited:
            return
        log.info(self.context)

    def __del__(self):
        self.quit()