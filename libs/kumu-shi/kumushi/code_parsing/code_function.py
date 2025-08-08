from pathlib import Path
import logging
from shellphish_crs_utils.models.indexer import GlobalVariableReference

_l = logging.getLogger(__name__)

class CodeFunction:
    """
    A class to represent a function in a code file.
    """
    def __init__(
        self,
        name: str,
        start_line: int,
        end_line: int,
        file_path: str | None | Path = None,
        code: str | None = None,
        global_vars: list[GlobalVariableReference] | None = None,
        version: str | None = None,
        is_macro: bool = False,
        function_index: str | None = None,
    ):
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.file_path = Path(file_path) if file_path else None
        self._code = code
        self.global_vars = global_vars or []
        self.version = version
        self.is_macro = is_macro
        if self._code or self.file_path:
            #FIXME: sometimes clang indexer thinks a MACRO is a function so that no { can be found
            if '{' in self.code:
                self.body_start_line = self.start_line + self.code[:self.code.index('{')].count('\n')
        else:
            self.body_start_line = None
        self.function_index = function_index


    @property
    def code(self):
        if not self._code:
            if not self.file_path or not self.file_path.exists():
                _l.warning("No code was provided and no file path exists. Returning None.")
                return None

            with open(self.file_path, "r") as f:
                lines = f.readlines()
                self._code = "".join(lines[self.start_line - 1 : self.end_line])

        return self._code

    @code.setter
    def code(self, code: str):
        self._code = code

    def copy(self):
        return CodeFunction(
            self.name,
            self.start_line,
            self.end_line,
            file_path=self.file_path,
            code=self._code,
            global_vars=self.global_vars.copy(),
            version=self.version,
        )

    def to_dict(self):
        return {
            "name": self.name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "file_path": str(self.file_path) if self.file_path else None,
            "code": self._code,
            "global_vars": self.global_vars,
            "version": self.version,
        }

    def __eq__(self, other):
        if not isinstance(other, CodeFunction):
            return False

        return self.name == other.name \
            and self.start_line == other.start_line \
            and self.end_line == other.end_line \
            and self.code == other.code \
            and self.global_vars == other.global_vars

    def __hash__(self):
        return hash((self.name, self.start_line, self.end_line, self.code, tuple(self.global_vars)))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return f"<{self.__class__.__name__}(name={self.name}, lines={self.start_line}:{self.end_line})>"
