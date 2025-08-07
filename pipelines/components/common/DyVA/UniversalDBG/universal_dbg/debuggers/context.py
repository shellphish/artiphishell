import re

from typing import List, Set
from pathlib import Path
from dataclasses import dataclass

@dataclass
class Variable:
    name: str
    value: str
    type: str

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.type or ''} {self.name} = {self.value}>"

@dataclass
class BacktraceLine:
    depth: int
    file: Path
    class_name: str
    function_name: str
    line: int
    instruction: int

    def __repr__(self):
        cls = self.class_name + '.' if self.class_name else ''
        insn = hex(self.instruction) + ' ' if self.instruction and self.instruction >= 0 else ' '
        file_loc = f"{self.file}:{self.line} " if self.file and self.line > 0 else ''
        return f"<{self.__class__.__name__}: [{self.depth}] {file_loc}{insn}{cls}{self.function_name}>"

class Backtrace:

    def __init__(self):
        self.bt: List[BacktraceLine] = []
        self._raw: str
    
    def update_bt(self, bt: List[BacktraceLine]):
        self.bt = bt
    
    def format(self):
        output = ""
        for line in self.bt:
            output += str(line) + "\n"
        return output

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
    
    def format(self) -> str:
        file_str = f"{self.file}:{self.line}" if self.file and self.line > 0 else ''
        func_str = f"{self.function}{(':' + str(self.line)) if self.line else ''}"
        if self.args:
            func_str += f"{'(' + ', '.join(str(arg) for arg in self.args) + ')'}"
        if self.addr:
            func_str += f"@{hex(self.addr)}"
        return f"File: {file_str}\nFunction: {func_str}\nLine: {self.text}"

class DebugContext:

    def __init__(self):
        self.locals: List[Variable] = []
        self.backtrace = Backtrace()
        self.frame: Frame = Frame()
        self._global_names: Set[str] = set()
        self.globals: List[Variable] = []
    
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
    
    def __str__(self):
        output = self.frame.format() + "\n"
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
            output += "\t" + '\n\t'.join(self.backtrace.format().split("\n"))
        return  output