from pathlib import Path
import logging

from .clang_cache import ClangCache
from .java_cache import JavaCache
from .code_function import CodeFunction
from .code_parser import CodeParser

from shellphish_crs_utils.function_resolver import FunctionResolver, RemoteFunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.symbols import SourceLocation, JavaInfo
_l = logging.getLogger(__name__)


class Code:
    """
    A class to represent code in a project which may have multiple files and functions.
    This class is based around being lazy-loaded, so that the code is not parsed until it is needed.
    """

    def __init__(
            self,
            source_root: Path,
            language: str | None = None,
            function_resolver: FunctionResolver | None = None,
            saved_resolver_cls: type[FunctionResolver] = None,
            saved_resolver_args: tuple = None,
    ):
        self.source_root = source_root
        self.language = language

        # cachable items
        self._function_resolver = function_resolver
        self._saved_resolver_args = saved_resolver_args or ()
        self._saved_resolver_cls = saved_resolver_cls or None
        self.always_reset_resolver = False
        self._functions = []

    def reinit_or_get_function_resolver(self):
        # this is really annoying, but we need to reset the function resolver if we transfer this object to
        # another process, so that it can be reinitialized with the correct arguments
        if self._function_resolver is None:
            self._function_resolver = self._saved_resolver_cls(*self._saved_resolver_args)

    def functions_by_name(self, funcname: str, focus_repo_only: bool = False, java_full_method: str = None) -> list[CodeFunction]:
        functions = []
        java_info = None
        if java_full_method is not None:
            class_path = "".join(java_full_method.split('.')[:-1])
            if class_path and '.' in class_path:
                java_info = JavaInfo(full_method_path=java_full_method, class_path=class_path)
        src_loc = SourceLocation(
            function_name=funcname,
            java_info=java_info,
        )
        function_indexes = self._function_resolver.resolve_source_location(srcloc=src_loc, focus_repo_only=focus_repo_only)
        if not function_indexes:
            #_l.info(f"No functions found for {funcname}")
            src_loc = SourceLocation(
                function_name="OSS_FUZZ_" + funcname,
                java_info=java_info,
            )
            function_indexes = self._function_resolver.resolve_source_location(srcloc=src_loc, focus_repo_only=focus_repo_only)
            if not function_indexes:
                return []
        if len(function_indexes) > 1:
            _l.debug(f"Multiple functions found for {funcname}: {function_indexes}")
        # trust the first one the function resolver returns
        for function_index in function_indexes:
            func = self.load_function_data(function_index[0], self.source_root)
            if func is None:
                continue
            functions.append(func)
        if len(functions) == 0:
            #_l.info(f"No functions found for {funcname}")
            return []
        return functions[:1]

    def load_function_data(self, function_index_key: str, source_root: Path) -> CodeFunction | None:
        functions = []
        if function_index_key is None:
            return None
        try:
            func_info = self._function_resolver.get(function_index_key)
        except Exception as e:
            _l.error(f"Error while loading function data: {e}", exc_info=True)
            return None
        focus_repo_relative_path = func_info.focus_repo_relative_path
        name = func_info.funcname

        if focus_repo_relative_path is None:
            _l.debug(f"Function %s has no focus repo relative path. Skipping.", name)
            index_dict, _ = self._function_resolver.find_matching_indices([function_index_key], scope='focus', can_include_self=False)
            match_index = index_dict.get(function_index_key, None)
            if match_index is None:
                return None
            # _l.info(f"Prev Function Index {function_index_key} has no focus repo relative path, trying to find a match in the focus repo: {match_index}")
            func_info = self._function_resolver.get(match_index)

        return self._func_from_func_info(func_info, function_index_key)

    def _func_from_func_info(self, func_info, function_index_key) -> CodeFunction:
        if func_info is None:
            _l.debug("Function info is None. Skipping.")
            return None

        name = func_info.funcname
        start_line = func_info.start_line
        end_line = func_info.end_line
        target_container_path = func_info.target_container_path
        code = func_info.code
        global_vars = func_info.global_variables
        focus_repo_relative_path = func_info.focus_repo_relative_path
        is_macro = "macro" in str(func_info.unique_identifier)

        if name is None or start_line is None or end_line is None or target_container_path is None:
            #_l.debug(f"Function info missing required fields for %s. Skipping. {name=}, {start_line=}, {end_line=}, {focus_repo_relative_path=}")
            return None

        if focus_repo_relative_path is None:
            return None

        if 'fuzz' in Path(focus_repo_relative_path).parts:
            _l.debug(f"Function {name} is in a fuzz directory {focus_repo_relative_path}. Skipping.")
            return None

        # make the filepath absolute
        abs_path = self.source_root / focus_repo_relative_path
        if abs_path is None or not abs_path.exists():
            _l.debug(f"File %s not found. Skipping this function parsing!", abs_path)
            return None

        return CodeFunction(name, start_line, end_line, focus_repo_relative_path, code=code, global_vars=global_vars, is_macro=is_macro, function_index=function_index_key)

    #
    #
    #

    def get_functions(self) -> list[CodeFunction]:
        if not self._functions:
            try:
                # we need to load the functions from the function resolver
                func_keys = self._function_resolver.keys()
                func_infos = self._function_resolver.get_many(func_keys)
                self._functions = [self._func_from_func_info(func_info, func_key) for func_key, func_info in func_infos.items() if func_info is not None]
                # filter out any None values
                self._functions = [func for func in self._functions if func is not None]
            except Exception as e:
                _l.error(f"Error while loading functions: {e}")
                self._functions = []

        return self._functions
    #
    # def refresh_functions(self, use_cache=False):
    #     """
    #     Refresh the functions in the code object.
    #     """
    #     version = self.version if not self.is_latest else None
    #     if use_cache:
    #         self._functions = self._code_cache.get_functions(self.source_root, version=version)
    #     else:
    #         self._functions = self._parse_functions(self.source_root, version=version)
    #
    # def _parse_functions(self, source_root: Path, version: str | None = None):
    #     """
    #     Parse the functions in the code object.
    #
    #     TODO: this needs to be fixed so that if you know the file and function name you want, you can just get
    #         that function, instead of parsing all of them.
    #     """
    #     if version is not None and version != self.DEFAULT_LATEST_VERSION:
    #         raise NotImplementedError("Versioned code parsing is not yet supported.")
    #
    #     suffix = CodeParser.LANG_TO_SUFFIX.get(self.language, None)
    #     if suffix is None:
    #         raise ValueError(f"Language {self.language} is not supported.")
    #
    #     _l.debug(f"Searching for files with suffix {suffix}...")
    #     code_files = list(source_root.glob(f"**/*{suffix}"))
    #     _l.debug(f"Found {len(code_files)} files. Parsing them now")
    #     functions = []
    #     for code_file in code_files:
    #         parser = CodeParser(code_file, lang=self.language)
    #         parser.parse()
    #         functions.extend(parser.functions.values())
    #
    #     return functions
