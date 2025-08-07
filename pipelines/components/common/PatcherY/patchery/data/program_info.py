import logging
import tempfile
import typing
from typing import Tuple
from pathlib import Path
from typing import List

import git

from .program_input import ProgramInput, ProgramInputType
from .program_poi import ProgramPOI
from patchery.code_parsing.code_parser import CodeParser

if typing.TYPE_CHECKING:
    from .patch import Patch
    from .executor import Executor

_l = logging.getLogger(__name__)


class ProgramInfo:
    def __init__(
        self,
        source_root: Path,
        lang: str,
        executor: "Executor" = None,
        benign_inputs: List[ProgramInput] = None,
        alerting_inputs: List[ProgramInput] = None,
        has_history: bool = True,
        has_reproducer: bool = False,
        is_kernel: bool = False,
    ):
        self.source_root = source_root
        self.lang: str = lang
        self.has_reproducer = has_reproducer

        self.executor = executor
        self.benign_inputs = benign_inputs or []
        self.alerting_inputs = alerting_inputs or []
        self._has_history = has_history or []

        self._repo = git.Repo(self.source_root) if self._has_history else None
        self.is_kernel = is_kernel

    def setup_program(self):
        pass

    def git_diff(self, patch: "Patch"):
        """
        Generates a Git diff given a patch.
        """
        if not self._has_history:
            raise ValueError("Program does not have a Git history.")

        if patch.diff is not None:
            return patch.diff

        # general methodology:
        # first, change the file in-place to the new code; then, use git diff to generate the diff
        # then revert the file back to the original code
        poi = patch.poi
        new_code = self.func_patch_to_new_file(poi, patch.new_code, lang=self.lang)
        with open(poi.file, "w") as f:
            f.write(new_code)
        # POI guy only gives us relative paths
        # relative_poi_path = Path(pois.file).resolve().absolute().relative_to(Path(self.source_root).resolve().absolute())
        relative_poi_path = Path(self.source_root).resolve().absolute()
        # relative_poi_path = patch.pois.file
        diff = self._repo.git.diff(relative_poi_path)
        self._repo.git.checkout("--", relative_poi_path)
        patch.diff = diff + "\n"
        return patch.diff

    @staticmethod
    def func_patch_to_new_file(target_poi: "ProgramPOI", new_code, lang="C") -> str:
        func_name = target_poi.function
        if  target_poi.func_startline is None:
            parser = CodeParser(target_poi.file, lang=lang)
            parser.parse()
            func = parser.functions[func_name]
            func_startline = func.start_line
            func_endline = func.end_line
        else:
            func_startline = target_poi.func_startline
            func_endline = target_poi.func_endline

        # load the old code
        with open(target_poi.file, "r") as fp:
            old_code = fp.read()

        # chunk the old code into lines
        old_code_lines = old_code.split("\n")
        new_function_lines = new_code.split("\n")

        # delete the old function, insert the new one
        new_code_lines = old_code_lines[: func_startline - 1] + new_function_lines + old_code_lines[func_endline:]

        return "\n".join(new_code_lines)

    @staticmethod
    def load_inputs_from_dir(input_dir: Path):
        inputs = []
        for input_file in input_dir.iterdir():
            inputs.append(ProgramInput(input_file.absolute().read_bytes(), ProgramInputType.FILE))

        return inputs

    def compile(self, patch: typing.Optional["Patch"] = None) -> Tuple[bool, str]:
        if patch is None:
            return self._compile_core()

        # we need to make the patch in an acceptable form
        git_diff = self.git_diff(patch)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(git_diff.encode())
            f.seek(0)
            patch_path = Path(f.name)
            return self._compile_core(patch_path=patch_path)

    def tiggers_alert(self, prog_input: ProgramInput) -> bool:
        if self.executor is None:
            _l.debug("No executor available.")
            return False

        return self.executor.generates_alerts(prog_input)

    def _compile_core(self, **kwargs):
        raise NotImplementedError("Subclasses must implement this method.")
