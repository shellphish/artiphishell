import logging
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple
import typing
import tempfile
import shutil
import subprocess
import git

from .program_alert import ProgramExitType
from .program_input import ProgramInput, ProgramInputType
from ..code_parsing.code import Code, CodeParser
from kumushi.data import PoICluster
from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver, RemoteFunctionResolver

_l = logging.getLogger(__name__)

class Program:
    def __init__(
        self,
        source_root: Path,
        function_resolver: FunctionResolver = None,
        crashing_inputs: list[ProgramInput] | None = None,
        language=None,
        should_init_resolver: bool = False,
    ):
        self.source_root = source_root
        self.language = language
        self._crashing_inputs = crashing_inputs or []
        self._should_init_resolver = should_init_resolver
        self.function_resolver = function_resolver if self._should_init_resolver else None
        # save the args to recreate the function resolver later (if needed for pickling)
        if isinstance(function_resolver, RemoteFunctionResolver):
            self._saved_resolver_args = (
                function_resolver.cp_name,
                function_resolver.project_id,
            )
            self._saved_resolver_cls = RemoteFunctionResolver
        elif isinstance(function_resolver, LocalFunctionResolver):
            self._saved_resolver_args = (
                function_resolver.functions_index_path,
                function_resolver.functions_jsons_path,
            )
            self._saved_resolver_cls = LocalFunctionResolver

        self._git_repo = git.Repo(str(self.source_root)) if (self.source_root / ".git").exists() else None
        self._versioned_code = {}
        self._latest_code = None
        self.crashing_function: typing.Optional[str] = None

    @property
    def crashing_input(self) -> ProgramInput | None:
        return self._crashing_inputs[0] or None

    def copy(self, **kwargs) -> "Program":
        """
        Returns a copy that is safe to use in parallel.
        """
        temp_dir = Path(tempfile.mkdtemp())
        shutil.copytree(self.source_root, temp_dir, dirs_exist_ok=True)
        return Program(
            temp_dir, crashing_inputs=self._crashing_inputs,
            language=self.language
        )

    def cleanup(self):
        """
        Cleans up the temporary directory.
        """
        if self.source_root.exists():
            shutil.rmtree(self.source_root)
        if self._git_repo is not None:
            self._git_repo.close()


    def setup_program(self):
        pass

    def reset_function_resolver(self):
        self.function_resolver = None
        self.code._function_resolver = None

    #
    # Source Code Lifting
    #

    @staticmethod
    def detect_source_language(source_root: Path):
        # TODO: implement this
        return "c"

    # @property
    # def versioned_code(self) -> dict[str, Code]:
    #     if self._versioned_code:
    #         return self._versioned_code
    #
    #     # there is no cache, we need to parse it ourselves
    #     if self._git_repo is not None:
    #         is_latest = True
    #         for commit in self._git_repo.iter_commits():
    #             self._versioned_code[commit.hexsha] = Code(
    #                 self.source_root, version=commit.hexsha, language=self.language, code_cache=self._code_cache,
    #                 is_latest=is_latest
    #             )
    #             is_latest = False
    #     else:
    #         self._versioned_code[Code.DEFAULT_LATEST_VERSION] = Code(
    #             self.source_root, version=Code.DEFAULT_LATEST_VERSION, language=self.language,
    #             code_cache=self._code_cache,
    #         )
    #
    #     return self._versioned_code

    @property
    def code(self) -> Code:
        if self._latest_code is None:
            is_latest = True

            #     # this is a git tracked project!
            #     if self._git_repo is not None:
            #         latest_commit = next(self._git_repo.iter_commits())
            #         self._latest_code = self.versioned_code[latest_commit.hexsha]
            #     else:
            #         self._latest_code = self.versioned_code[Code.DEFAULT_LATEST_VERSION]
            self._latest_code = Code(
                self.source_root,
                language=self.language,
                function_resolver=self.function_resolver,
                saved_resolver_args=self._saved_resolver_args,
                saved_resolver_cls=self._saved_resolver_cls,
            )

        return self._latest_code

    #
    # Diffing
    #

    def _restore_src(self):
        _l.debug("Restoring the source code...")
        repo = git.Repo(self.source_root)
        repo.git.reset("--hard")
        _l.debug("Source code restored")

    def git_diff(self, patch: "Patch"):
        """
        Generates a Git diff given a patch.
        """
        if self._git_repo is None:
            raise ValueError("Program does not have a Git history.")

        if patch.diff is not None:
            return patch.diff

        repo = git.Repo(str(self.source_root))
        # general methodology:
        # first, change the file in-place to the new code; then, use git diff to generate the diff
        # then revert the file back to the original code
        patched_funcs = patch.patched_functions
        grouped_funcs = defaultdict(list)

        for patched_func in patched_funcs:
            grouped_funcs[patched_func.file].append(patched_func)
        for patched_file in grouped_funcs:
            new_code = self.file_patch_to_new_file(grouped_funcs[patched_file], lang=self.language)
            with open(patched_file, "w") as f:
                f.write(new_code)

        source_path = Path(self.source_root).resolve().absolute()
        # relative_poi_path = patch.pois.file
        diff = repo.git.diff(source_path)
        repo.git.checkout("--", source_path)
        patch.diff = diff + "\n"

        self._restore_src()

        return patch.diff

    def update_pois_for_src_path(self, poi_clusters: list[PoICluster]) -> list[PoICluster]:
        new_clusters = []
        for cluster in poi_clusters:
            updated_pois = []
            for poi in cluster.pois:
                poi.function.file_path = self.source_root / poi.function.file_path
                updated_pois.append(poi)
            new_clusters.append(PoICluster.from_pois(updated_pois))

        return new_clusters

    @staticmethod
    def file_patch_to_new_file(grouped_funcs: "List[PatchedFunction]", lang="C") -> str:
        # read the original code from file
        with open(grouped_funcs[0].file, "r") as fp:
            old_code = fp.read()

        # chunk the old code into lines
        old_code_lines = old_code.split("\n")

        replacements = []

        for patched_func in grouped_funcs:
            func_name = patched_func.function_name

            # If func_startline is None, use parser to find start and end lines
            if patched_func.init_start_line is None:
                parser = CodeParser(patched_func.file, lang=lang)
                parser.parse()
                func = parser.functions[func_name]
                patched_func.init_start_line = func.start_line
                patched_func.init_end_line = func.end_line

        for patched_func in grouped_funcs:
            func_startline = patched_func.init_start_line
            func_endline = patched_func.init_end_line

            new_function_lines = patched_func.new_code.split("\n")
            # Add the start line, end line, and new function lines to the replacements list
            replacements.append((func_startline, func_endline, new_function_lines))

            # Sort the replacements in reverse order by the start line to avoid line shifts during replacements
        replacements = sorted(replacements, reverse=False)

        # Track the cumulative change in line numbers
        line_offset = 0

        for start, end, new_code in replacements:
            # Apply line_offset to the current start and end
            adjusted_start = start + line_offset
            adjusted_end = end + line_offset

            # Compute the difference in number of lines between old and new code
            old_lines_count = end - start + 1
            new_lines_count = len(new_code)
            line_offset += new_lines_count - old_lines_count

            # Apply the replacement to the old_code_lines
            old_code_lines = old_code_lines[:adjusted_start - 1] + new_code + old_code_lines[adjusted_end:]

        # Return the modified code as a string
        return "\n".join(old_code_lines)

    @staticmethod
    def load_inputs_from_dir(input_dir: Path):
        inputs = []
        for input_file in input_dir.iterdir():
            inputs.append(ProgramInput(input_file.absolute().read_bytes(), ProgramInputType.FILE))

        return inputs

    #
    # Compilation & Building
    #

    def compile(self, patch: typing.Optional["Patch"] = None, edited_in_place=False, flags=None, **kwargs) -> tuple[bool, str]:
        git_diff = None
        source_path = str(Path(self.source_root).resolve().absolute())
        if patch is None:
            if not edited_in_place:
                # we have a compile chain which requires no edits, we just need the basic compilation
                return self._compile_core(flags=flags, **kwargs)

            # we have a compile chain where we did not make a Patch object, but instead edited in place
            # which requires that we reset the source after we are done
            repo = git.Repo(source_path)
            git_diff = repo.git.diff(source_path) + "\n"
            # stash the edits
            repo.git.stash()

        # we need to make the patch in an acceptable form
        if git_diff is None and patch is not None:
            git_diff = self.git_diff(patch)

        if git_diff is None:
            raise ValueError("Failed to create diff in a scenario where we either had no Patch or no edits")

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(git_diff.encode())
            f.seek(0)
            patch_path = Path(f.name)
            compile_res = self._compile_core(patch_path=patch_path, patch_obj=patch, flags=flags, **kwargs)

        return compile_res

    def _compile_core(self, **kwargs):
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    def rsync_copy_dir(source: Path, dest: Path):
        cmd = ["rsync", "-raz", "--delete", str(source) + "/", str(dest) + "/"]
        subprocess.run(cmd, check=True)
        return True

    #
    # Execution
    #

    def _check_functionality_core(self, **kwargs) -> tuple[ProgramExitType, typing.Optional[str]]:
        raise NotImplementedError("Subclasses must implement this method.")

    def check_functionality(self, patch: typing.Optional["Patch"] = None, **kwargs) -> tuple[ProgramExitType, typing.Optional[str]]:
        # we need to make the patch in an acceptable form
        git_diff = self.git_diff(patch) if patch is not None else None
        if patch is not None and git_diff is None:
            raise ValueError("Failed to create diff in a scenario where we either had no Patch or no edits")

        if git_diff:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(git_diff.encode())
                f.seek(0)
                patch_path = Path(f.name)
                return self._check_functionality_core(patch_path=patch_path, patch_obj=patch, **kwargs)
        else:
            return self._check_functionality_core(**kwargs)

    def execute(self, prog_input: ProgramInput):
        raise NotImplementedError

    def generates_alerts(self, prog_input: ProgramInput) -> Tuple[ProgramExitType, str | None, list]:
        raise NotImplementedError

    def triggers_alert(self, prog_input: ProgramInput) -> bool:
        raise NotImplementedError
