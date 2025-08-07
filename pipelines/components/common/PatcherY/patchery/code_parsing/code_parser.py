from pathlib import Path
import tempfile
from typing import Dict, Optional
import logging

from .code_function import CodeFunction
from .code_parser_backend import CodeParserBackend
from .tree_sitter_parser import get_function_info

_l = logging.getLogger(__name__)


class CodeParser:
    LANG_SUFFIXS = {".c", ".cpp", ".cxx", ".cc", ".java"}

    def __init__(self, code_file: Path, lang="C") -> None:
        self.code_file = Path(code_file)
        self.lang = self.normalize_lang_name(lang)
        self._code: Optional[str] = None
        self._code_lines = []
        self._backend = self._backend_from_lang(self.lang)
        self.functions: Dict[str, CodeFunction] = {}

    def parse(self):
        if not self.code_file.exists():
            raise ValueError(f"File {self.code_file} does not exist.")

        with open(self.code_file, "r") as f:
            self._code = f.read()
            self._code_lines = self._code.split("\n")

        if self._backend == CodeParserBackend.CLANG:
            self._parse_clang()
        elif self._backend == CodeParserBackend.TREE_SITTER:
            self._parse_tree_sitter()

        if not self.functions:
            _l.warning("This file does not contain any functions. Probably is a .h file. Skipping.")
            # raise ValueError("The parser failed to find any functions in the text")

    def function_containing_line(self, line: int) -> str:
        if not self.functions:
            self.parse()

        ordered_funcs = sorted(self.functions.values(), key=lambda x: x.start_line)
        for func in ordered_funcs:
            if func.start_line <= line <= func.end_line:
                return func.name
        else:
            _l.warning(f"No function found for line {line}. Skipping.")
            return None
            # raise ValueError(f"No function found for line {line}")

    def _parse_clang(self):
        """
        This parser is disabled for now since it is a little slow. Instead, we use cached data from the clang_indexer
        to do the same thing.
        """
        from clang_indexer.indexer import ClangIndexer
        from clang_indexer.db import FunctionInfo, MethodInfo

        file_infos = ClangIndexer.collect_info_in_file(str(self.code_file))
        for file_info in file_infos:
            # we only care about functions for now
            if not isinstance(file_info, (FunctionInfo, MethodInfo)):
                continue

            gvars_info = file_info.global_variables
            gvars = []
            if gvars_info:
                gvar_info = gvars_info[0]
                gvars = list(gvar_info.values())

            if isinstance(file_info, MethodInfo):
                # XXX: yes, this is a hack
                name = "::".join(file_info.full_name.split("::")[1:])
                self.functions[name] = CodeFunction(name, file_info.start_line, file_info.end_line, global_vars=gvars)
            elif isinstance(file_info, FunctionInfo):
                self.functions[file_info.name] = CodeFunction(
                    file_info.name, file_info.start_line, file_info.end_line, global_vars=gvars
                )

    def _parse_tree_sitter(self):
        func_info = get_function_info(self._code, self.lang)
        for func_name, vals in func_info.items():
            start_line, end_line = vals
            self.functions[func_name] = CodeFunction(func_name, start_line, end_line)

    def func_code(self, func_name: str) -> str:
        if not self.functions:
            self.parse()

        func = self.functions.get(func_name)
        if not func:
            raise ValueError(f"Function {func_name} not found in the code.")

        if func.code is None:
            function_code = "\n".join(self._code_lines[func.start_line - 1 : func.end_line])
            func.code = function_code
            self.functions[func_name] = func

        return func.code

    @classmethod
    def from_code_string(cls, code_string: str, target_function: str, lang="C") -> "CodeParser":
        suffix = cls._suffix_from_lang(lang)
        with tempfile.NamedTemporaryFile(delete=True, suffix=suffix) as temp_file:
            temp_file.write(code_string.encode())
            temp_file.seek(0)

            parser = cls(Path(temp_file.name), lang=lang)
            parser.parse()
            return parser

    @staticmethod
    def normalize_lang_name(lang):
        lang = lang.lower()
        if lang in ["c++", "cpp", "cxx", "cc"]:
            return "cpp"
        return lang

    @staticmethod
    def _suffix_from_lang(lang):
        lang = CodeParser.normalize_lang_name(lang)
        if lang == "c":
            return ".c"
        elif lang == "cpp" or lang == "c++":
            return ".cpp"
        elif lang == "java":
            return ".java"
        else:
            raise ValueError(f"Unsupported language: {lang}")

    @staticmethod
    def _backend_from_lang(lang):
        lang = CodeParser.normalize_lang_name(lang)
        if lang == "c" or lang == "cpp":
            return CodeParserBackend.TREE_SITTER
        elif lang == "java":
            return CodeParserBackend.TREE_SITTER
        else:
            raise ValueError(f"Unsupported language: {lang}")
