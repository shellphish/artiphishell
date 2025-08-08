from typing import List, Set, Dict, Any
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Breakpoint:
    file: Path
    line: int
    function: str
    addr: int
    class_name: str = None
    id: str = None

    def __repr__(self):
        if self.file and self.line:
            return f"<{self.__class__.__name__}: {self.file}:{self.line}>"
        elif self.class_name:
            return f"<{self.__class__.__name__}: {self.class_name}:{self.line}>"
        elif self.function:
            return f"<{self.__class__.__name__}: {self.function}>"
        elif self.addr:
            return f"<{self.__class__.__name__}: {hex(self.addr)}>"


@dataclass
class Variable:
    name: str
    value: str
    type: str

    def copy(self) -> "Variable":
        return Variable(name=self.name, value=self.value, type=self.type)

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.type or ''} {self.name} = {self.value}>"


@dataclass
class Register:
    name: str
    value: int
    changed: bool

    def copy(self) -> "Register":
        return Register(name=self.name, value=self.value, changed=self.changed)

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.name} = {hex(self.value)} (changed: {self.changed})>"


@dataclass
class BacktraceLine:
    depth: int
    file: Path
    class_name: str
    function_name: str
    line: int
    instruction: int
    args: List[Variable] = None

    def copy(self) -> "BacktraceLine":
        return BacktraceLine(
            depth=self.depth,
            file=self.file,
            class_name=self.class_name,
            function_name=self.function_name,
            line=self.line,
            instruction=self.instruction,
            args=[arg.copy() for arg in self.args] if self.args else None
        )

    def __repr__(self):
        cls = self.class_name + "." if self.class_name else ""
        insn = hex(self.instruction) + " " if self.instruction and self.instruction >= 0 else " "
        file_loc = f"{self.file}:{self.line} " if self.file and self.line > 0 else ""
        return f"<{self.__class__.__name__}: [{self.depth}] {file_loc}{insn}{cls}{self.function_name}({', '.join(str(arg) for arg in self.args or [])})>"


class Backtrace:
    def __init__(self):
        self.bt: List[BacktraceLine] = []
        self._raw: str = ""

    def update_bt(self, bt: List[BacktraceLine]):
        self.bt = bt

    def format(self):
        output = ""
        for line in self.bt:
            output += str(line) + "\n"
        return output
    
    def copy(self) -> "Backtrace":
        copy_bt = Backtrace()
        copy_bt.bt = [line.copy() for line in self.bt]
        copy_bt._raw = self._raw
        
        return copy_bt

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.bt}>"


@dataclass
class Frame:
    addr: int = None
    function: str | int = None
    args: List[Variable] = None
    file: Path = None
    line: int = None
    text: str = None
    depth: int = 0

    def format(self) -> str:
        file_str = f"{self.file}:{self.line}" if self.file and self.line > 0 else ""
        func_str = f"{self.function}{(':' + str(self.line)) if self.line else ''}"
        if self.args:
            func_str += f"{'(' + ', '.join(str(arg) for arg in self.args) + ')'}"
        if self.addr:
            func_str += f"@{hex(self.addr)}"
        return f"File: {file_str}\nFunction: {func_str}\nSource Line Text: {self.text}"

    def copy(self) -> "Frame":
        return Frame(
            addr=self.addr,
            function=self.function,
            args=[arg.copy() for arg in self.args] if self.args else None,
            file=self.file,
            line=self.line,
            text=self.text,
            depth=self.depth
        )

class DebugContext:
    def __init__(self):
        self.locals: List[Variable] = []
        self.backtrace = Backtrace()
        self.frame: Frame = Frame()
        self._global_names: Set[str] = set()
        self.globals: List[Variable] = []
        self.registers: Dict[str, Register] = {}
        self.pc: int = None

    def track_global(self, name: str):
        self._global_names.add(name)

    def untrack_global(self, name: str):
        self._global_names.remove(name)

    def get_globals(self):
        return self._global_names

    def update_globals(self, globals: List[Variable]):
        self.globals = globals

    def update_locals(self, locals: List[Variable]):
        self.locals = locals

    def update_backtrace(self, bt: List[BacktraceLine]):
        self.backtrace.update_bt(bt)

    def update_registers(self, registers: Dict[str, Register]):
        self.registers.update(registers)
    
    def copy(self) -> "DebugContext":
        context_copy = DebugContext()
        context_copy.locals = [x.copy() for x in self.locals]
        context_copy.backtrace = self.backtrace.copy()
        context_copy.frame = self.frame.copy()
        context_copy._global_names = self._global_names.copy()
        context_copy.globals = [x.copy() for x in self.globals]
        context_copy.registers = {k: v.copy() for k, v in self.registers.items()}
        context_copy.pc = self.pc

        return context_copy

    def reset(self):
        self.locals = []
        self.backtrace = Backtrace()
        self.frame = Frame()
        self.globals = []
        self.registers = {}

    def __str__(self):
        output = self.frame.format() + "\n"
        if self.registers:
            output += "Registers: "
            output += ", ".join([f"{reg.name} = {hex(reg.value)}" for reg in self.registers.values() if reg.changed])
            output += "\n"
        if self.globals:
            output += "Global Variables:\n"
            for var in self.globals:
                output += f"\t{var}\n"
        if self.locals:
            output += "Local Variables:\n"
            for var in self.locals:
                output += f"\t{var}\n"
        if self.backtrace.bt:
            output += "\nBacktrace:\n"
            output += "\t" + "\n\t".join(self.backtrace.format().split("\n"))
        return output

    def to_dict(self) -> dict[str, Any]:
        out_context = {
            "frame": {
                "args": [{"type": arg.type, "name": arg.name, "value": arg.value} for arg in (self.frame.args or [])],
                "file": str(self.frame.file),
                "line_no": self.frame.line,
                "src_line": self.frame.text,
                "function": self.frame.function,
            },
            "backtrace": [str(b) for b in self.backtrace.bt],
            "locals": [{"type": l_var.type, "name": l_var.name, "value": l_var.value} for l_var in self.locals],
            "globals": [{"type": g_var.type, "name": g_var.name, "value": g_var.value} for g_var in self.globals],
            "raw": str(self),
        }
        return out_context
 