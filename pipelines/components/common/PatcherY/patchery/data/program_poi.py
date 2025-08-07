from pathlib import Path
from typing import List


class ProgramPOI:
    """
    A Program Point of Interest is a point in the program where a bug has been found.
    """

    def __init__(
        self,
        file: Path,
        function: str,
        lineno: int = None,
        linetext=None,
        report: str = None,
        alert: str = None,
        git_diff: str = None,
        global_variables: List[str] = None,
        func_src: str = "",
        func_startline: int = None,
        debug_info: str = "",
        func_endline: int = None,
    ):
        self.file = Path(file)
        self.function = function
        self.lineno = lineno
        self.report = report
        self.alert = alert
        self.linetext = linetext
        self.git_diff = git_diff
        self.global_variables = [] if global_variables is None else global_variables
        self.func_src = func_src
        self.func_startline = func_startline
        self.debug_info = debug_info
        self.func_endline = func_endline

    def __str__(self):
        poi_str = f"<{self.__class__.__name__} file={self.file}, func={self.function}, line={self.lineno}"
        if self.report and isinstance(self.report, str):
            poi_str += f", report={len(self.report)}"
        poi_str += ">"
        return poi_str

    def __repr__(self):
        return self.__str__()

    def to_aicc_format(self):
        return {
            "source_location": {
                "relative_file_path": str(self.file),
                "function": self.function,
                "line_number": self.lineno,
                "reason": self.report,
            }
        }
