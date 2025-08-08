import json
from pathlib import Path
import logging

from shellphish_crs_utils.function_resolver import FunctionIndex, RemoteFunctionResolver

from .code_function import CodeFunction

_l = logging.getLogger(__name__)


class ClangCache:
    FUNC_DIR = "FUNCTION"
    MACRO_DIR = "MACRO"
    METHOD_DIR = "METHOD"

    def __init__(
            self,
            func_indices: dict[str, dict[str, int]],
            func_json_dir: Path,
            indices_by_commit: dict[str, dict[str, int]] | None = None,
            changed_func_by_commits: Path | None = None,
    ):
        self._func_indices = func_indices
        self._func_json_dir = Path(func_json_dir) if func_json_dir else None
        self._indices_by_commit = indices_by_commit
        self._changed_func_by_commits = Path(changed_func_by_commits) if changed_func_by_commits else None

    def get_functions(self, source_root: Path, version: str | None = None, project_name=None) -> list[CodeFunction]:
        if project_name is None:
            source_root = Path(source_root).absolute() if source_root else None
            project_name = source_root.name
            # TODO: when we refactor for multi projects we will need to actually set project_name
            project_name = ""

        if version is not None and self._changed_func_by_commits is not None:
            if not self._changed_func_by_commits.exists() or not self._changed_func_by_commits.is_dir():
                raise FileNotFoundError(f"File {self._changed_func_by_commits} not found.")

            # iterate the dir to find all the commits
            for commit_dir in self._changed_func_by_commits.glob("*_*"):
                cmt_order, cmt_hash = commit_dir.name.split("_")
                try:
                    cmt_order = int(cmt_order, 0)
                except ValueError:
                    continue

                if cmt_hash == version:
                    break
            else:
                raise ValueError(f"Commit {version} not found in the cache.")

            # now we have the commit dir
            indexer_dir = commit_dir
        else:
            indexer_dir = self._func_json_dir
        functions_dir = indexer_dir / project_name / self.FUNC_DIR
        if not functions_dir.exists() or not functions_dir.is_dir():
            raise FileNotFoundError(f"Directory {functions_dir} not found.")

        method_dir = indexer_dir / project_name / self.METHOD_DIR
        if not method_dir.exists() or not method_dir.is_dir():
            raise FileNotFoundError(f"Directory {method_dir} not found.")

        functions = []
        parsed_functions = self.load_function_data(functions_dir, source_root, version)
        functions.extend(parsed_functions)

        parsed_methods = self.load_function_data(method_dir, source_root, version)
        functions.extend(parsed_methods)

        return functions

    def load_function_data(self, functions_dir, source_root, version):
        functions = []
        for func_json in functions_dir.glob("*.json"):
            try:
                func_info = FunctionIndex.model_validate(json.loads(func_json.read_text()))
            except json.JSONDecodeError:
                _l.critical(f"Error decoding %s as json. Skipping.", func_json)
                continue
            name = func_info.funcname
            start_line = func_info.start_line
            end_line = func_info.end_line
            focus_repo_relative_path = func_info.focus_repo_relative_path
            target_container_path = func_info.target_container_path
            code = func_info.code
            global_vars = func_info.global_variables

            if name is None or start_line is None or end_line is None or target_container_path is None:
                _l.critical(f"Function info missing required fields for %s. Skipping. {name=}, {start_line=}, {end_line=}, {focus_repo_relative_path=}")
                continue

            if focus_repo_relative_path is None:
                _l.debug(f"Function %s has no focus repo relative path. Skipping.", name)
                continue

            # make the filepath absolute
            abs_path = source_root / focus_repo_relative_path
            if abs_path is None or not abs_path.exists():
                _l.critical(f"File %s not found. Skipping this function parsing!", abs_path)
                continue

            functions.append(
                CodeFunction(name, start_line, end_line, focus_repo_relative_path, code=code, global_vars=global_vars,
                             version=version)
            )
        return functions
