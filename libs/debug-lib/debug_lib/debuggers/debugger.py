import logging

from pathlib import Path
from typing import Dict, List, Any
from functools import wraps

from debug_lib.debuggers.context import DebugContext, Variable, Breakpoint, Register, BacktraceLine

log = logging.getLogger(__name__)


def check_exited(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.exited:
            self.breakpoints = []
            return
        return func(self, *args, **kwargs)

    return wrapper


def update_context(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        result = func(self, *args, **kwargs)
        if not self.exited:
            self.update_context()
        return result

    return wrapper


def register(*decorators):
    def wrapper(func):
        for deco in decorators:
            func = deco(func)
        func._decorators = decorators
        return func

    return wrapper


# Create the metaclass
class MetaWithDecorator(type):
    def __new__(cls, name, bases, dct):
        # Find methods in base classes that have decorators
        decorated_methods = {}
        for base in bases:
            for attr_name in dir(base):
                attr = getattr(base, attr_name)
                if callable(attr) and hasattr(attr, "_decorators"):
                    decorated_methods[attr_name] = attr._decorators

        # Apply decorators to the methods in the child class
        for attr_name, decorators in decorated_methods.items():
            if attr_name in dct:
                func = dct[attr_name]
                for decorator in decorators:
                    func = decorator(func)
                dct[attr_name] = func

        return super().__new__(cls, name, bases, dct)


class Debugger(metaclass=MetaWithDecorator):
    def __init__(self, program: Path, argv: List[str] = None, stdin: bytes = None):
        self.program = program
        self.argv: List[str] = argv
        self.stdin: bytes = stdin
        self.stdout: List[str] = []
        self.context = DebugContext()
        self.breakpoints: List[Breakpoint] = []
        self.exited = False

    @register(update_context)
    def run(self):
        """
        Executes the program in the context of the debugger.

        This method should be implemented by subclasses to define the specific behavior of the debugger.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def quit(self):
        """
        Quit the debugger.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def step(self, num=1):
        """
        Executes the next step in the debugging process.

        Args:
            num (int): The number of lines to step through. Default is 1.

        Raises:
            NotImplementedError: This method must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def step_insn(self, num=1):
        """
        Steps through the specified number of instructions in the program.

        Args:
            num (int): The number of instructions to step through. Default is 1.

        Raises:
            NotImplementedError: This method must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def next(self, num=1):
        """
        Moves the debugger to the next instruction.

        Args:
            num (int): The number of lines to move forward (default is 1).

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def next_insn(self, num=1):
        """
        Advances the debugger to the next instruction.

        Args:
            num (int): The number of instructions to advance. Default is 1.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def up(self, num=1):
        """
        Move the debugger up to the next backtrace level.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def down(self, num=1):
        """
        Move the debugger down to the next backtrace level.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def finish(self):
        """
        Finish the execution of the current function.

        This method should be implemented by subclasses to perform any necessary cleanup or finalization steps.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited, update_context)
    def continue_execution(self):
        """
        Continue the execution of the program being debugged.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited)
    def program_counter(self) -> int:
        """
        Returns the current value of the program counter or equivalent concept.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited)
    def set_breakpoint(self, *args, **kwargs):
        """
        Sets a breakpoint in the debugger.
        This method must be implemented by subclasses to update the `self.breakpoints` attribute.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            NotImplementedError: If the method is not implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @register(check_exited)
    def remove_breakpoint(self, bp: Breakpoint):
        """
        Removes the specified breakpoint from the debugger.
        This method must be implemented by subclasses to update the `self.breakpoints` attribute.

        Args:
            bp (Breakpoint): The breakpoint to be removed.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def registers(self) -> Dict[str, Register]:
        """
        Get the registers of the debugger.

        Returns:
            A dictionary containing the registers of the debugger.
        """
        return self.context.registers

    @property
    def local_variables(self) -> List[Variable]:
        """
        Returns a list of local variables in the current context.

        Returns:
            A list of Variable objects representing the local variables.
        """
        return self.context.locals

    @property
    def global_variables(self) -> List[Variable]:
        """
        Returns the global variables of the debugger's context.

        Returns:
            A list of Variable objects representing the global variables.
        """
        return self.context.globals

    @property
    def frame(self):
        """
        Returns the current frame of the debugger.
        """
        return self.context.frame

    @property
    def backtrace(self) -> List[BacktraceLine]:
        """
        Retrieves the backtrace of the debugger.

        Returns:
            A list of `BacktraceLine` objects representing the backtrace.
        """
        return self.context.backtrace.bt

    def get_stack(self, size=0x10):
        """
        Retrieves the stack data from the debugger.

        Args:
            size (int): The size of the stack to retrieve. Defaults to 0x10.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def update_context(self):
        """
        Updates the context of the debugger by updating the backtrace, frame, and locals.
        This method is called from the @update_context decorator.
        """
        self.update_backtrace()
        self.update_frame()
        self.update_locals()

    def update_frame(self):
        """
        Updates the current frame of the debugger.

        This method should be implemented by subclasses to provide the necessary logic for updating the frame.
        Raises:
            NotImplementedError: If the method is not implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def update_backtrace(self):
        """
        Updates the backtrace information for the debugger.

        This method should be implemented by subclasses to provide the specific
        implementation for updating the backtrace.

        Raises:
            NotImplementedError: If the method is not implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def update_locals(self):
        """
        Updates the local variables in the debugger.

        This method should be implemented by subclasses to provide the specific logic for updating the local variables
        in the debugger.

        Raises:
            NotImplementedError: This method must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def track_global(self, global_variable_name):
        """
        Add global variable to Debugger Context Tracking

        Parameters:
        - global_variable_name (str): The name of the global variable to track.

        Returns:
        None
        """
        self.context.track_global(global_variable_name)

    def untrack_global(self, global_variable_name):
        """
        Remove a global variable from the Debugger Context Tracking.

        Parameters:
        - global_variable_name (str): The name of the global variable to be removed.

        Returns:
        None
        """
        self.context.untrack_global(global_variable_name)

    def raw(self, cmd) -> Any:
        """
        This function passes the command to the underlying debugging engine for advanced usage

        Args:
            cmd: The command to be passed to the debugging engine

        Returns:
            The result of the command execution

        Raises:
            NotImplementedError: If the method is not implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement this method")

    def print_context(self):
        """
        Prints the context of the debugger.

        If the debugger has exited, nothing is printed.
        """
        if self.exited:
            return
        log.info(self.context)

    def __del__(self):
        self.quit()
