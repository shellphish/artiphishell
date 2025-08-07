from typing import Optional, List
from pathlib import Path
import json
import re

from ..report import Report
from ...data import ProgramPOI, ProgramInfo
from ...code_parsing import CodeParser

"""
filein_harness_real:mock_vp_c_11:
  file: samples/mock_vp.c
  func: func_a()
  key_index: samples/mock_vp.c:7:1::void func_a()
  line: '11'
  unique_to_crash: false
  violations:
  - is: max(i)==3
    was: max(i)==1
  - is: max(buff)==93825004370356
    was: max(buff)==93825004370336
"""


class InvarianceViolation:
    def __init__(self, prev=None, curr=None):
        self.prev: Optional[str] = prev
        self.curr: Optional[str] = curr

    def __str__(self):
        return f"<Violation: {self.prev} -> {self.curr}>"

    def __repr__(self):
        return str(self)


class InvarianceReport(Report):
    def __init__(self, raw_data: dict, unique_name: Optional[str] = None):
        super().__init__(raw_data)
        self._unique_name: Optional[str] = unique_name
        self.violations: List[InvarianceViolation] = []
        self.file_path: Optional[Path] = None
        self.line: Optional[int] = None
        self.unique_to_crash: bool = False
        self.function_name: Optional[str] = None
        self.function_index: Optional[str] = None
        self._parse_invariance_report(raw_data)

    @classmethod
    def from_raw_data(cls, raw_data: dict, unique_name: Optional[str] = None):
        report = cls(raw_data, unique_name=unique_name)
        return report

    def to_poi(self, prog_info, function_indices, function_json_dir, report=None) -> ProgramPOI:
        
        src = Path(prog_info._run_script) / "src"
        with open(function_indices, "r") as f:
            function_indices = json.load(f)
        function_json = Path(function_json_dir) / function_indices[self.function_index]
        with open(function_json, "r") as f:
            function_info = json.load(f)
        file_path = function_info['filepath']
        full_src_path = src / file_path
        func_name = function_info['funcname']
        func_name = re.sub(r'\(.*?\)', "", func_name)
        func_startline = function_info['start_line']
        func_endline = function_info['end_line']
        func_src = function_info['code']
        global_variables = [ variable.get('declaration',"") for variable in function_info['global_variables']]
        # code_parser = CodeParser(full_src_path, lang=prog_info.lang)
        # code_parser.parse()
        # function_name = code_parser.function_containing_line(self.line)
        return ProgramPOI(full_src_path, func_name, lineno=self.line, global_variables=global_variables, func_startline=func_startline, func_endline=func_endline,func_src=func_src, report=report or self.render())

    def _parse_invariance_report(self, raw_data: dict):
        self.file_path = Path(raw_data["file"])
        self.line = int(raw_data["line"])
        self.unique_to_crash = bool(raw_data["unique_to_crash"])
        self.function_name = raw_data.get("func", None)
        self.function_index = raw_data.get("key_index", None)
        for violation in raw_data["violations"]:
            self.violations.append(InvarianceViolation(prev=violation["was"], curr=violation["is"]))

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.file_path}:{self.line} violations={len(self.violations)}>"

    def __repr__(self):
        return str(self)

    def render(self) -> str:
        if not self.violations:
            return ""

        violations_str = ""
        for i, violation in enumerate(self.violations):
            violations_str += f"### Violation {i+1}\n"
            violations_str += f"Should Have Been: {violation.prev}\n"
            violations_str += f"Is: {violation.curr}\n"
            violations_str += "\n"

        output = "## Anomalous Variable Values\n"
        output += "Below you will find violations on what values should have been, and what they are now:\n\n"
        output += violations_str
        return output
