import os
import sys
import subprocess
import textwrap
import unittest
import tempfile
from pathlib import Path
import shutil
from tempfile import NamedTemporaryFile
from subprocess import run, CalledProcessError
from typing import Optional

import git


import patchery
from patchery import Patcher
from patchery.data import (
    Patch,
    ProgramPOI,
    ProgramInfo,
    AICCProgramInfo,
    ProgramInput,
    ProgramInputType,
    Executor,
    ProgramExitType,
)
from patchery.verifier.verification_passes import CompileVerificationPass
from patchery.code_parsing.code_parser import CodeParser
from patchery.utils import WorkDirContext

from common import TARGETS, PATCHES, REPORTS, TEST_DIR, GENERIC_TEST_DIR

#
# Testing Utils
#

FAKE_GIT_REPOS = [
    TARGETS / "adams",
    TARGETS / "hamlin/challenge/src",
]

GIT_REPOS = [TARGETS / "jenkins/src/plugins/pipeline-util-plugin", TARGETS / "kernel/src"]


def apply_patch_text(repo_path, target_file, patch_file_path) -> str:
    repo_path = Path(repo_path)
    target_file = Path(target_file)
    patch_file_path = Path(patch_file_path)

    if not patch_file_path.exists():
        raise FileNotFoundError(f"The patch file {patch_file_path} does not exist.")

    repo = git.Repo(str(repo_path))
    repo.git.apply(patch_file_path)

    # return the new code
    with open(target_file, "r") as f:
        patched_code = f.read()

    # Reset the repo
    repo.git.reset("--hard")

    return patched_code


def patch_func_from_patch_file(repo_path, target_file, func_name, patch_file_path, lang="C") -> str:
    """
    Applies a patch to a file and extracts the target function.
    """
    new_file_text = apply_patch_text(repo_path, target_file, patch_file_path)
    parser = CodeParser.from_code_string(new_file_text, func_name, lang=lang)
    return parser.func_code(func_name)


def setup_testcase():
    # run through all targets and init them
    for repo_dir in FAKE_GIT_REPOS:
        if not (repo_dir / ".git").exists():
            repo = git.Repo.init(repo_dir)
            repo.git.add(".")
            repo.git.commit("-m", "init")


def teardown_testcase():
    # remove all git repos .git dirs
    for repo_dir in FAKE_GIT_REPOS:
        git_dir = repo_dir / ".git"
        if git_dir.exists():
            repo = git.Repo(str(repo_dir))
            repo.git.reset("--hard")
            shutil.rmtree(git_dir)

    for repo_dir in GIT_REPOS:
        reset_repo_path(repo_dir)


def reset_repo_path(repo_dir: Path):
    if repo_dir.exists():
        repo = git.Repo(str(repo_dir))
        repo.git.reset("--hard")


#
# Mocking/Testing Classes
#


class SimpleExecutor(Executor):
    def __init__(self, run_script_path: Path, **kwargs):
        self._runner_path: Path = Path(run_script_path).resolve().absolute()
        super().__init__(**kwargs)

    def generates_alerts(self, prog_input: ProgramInput, *args) -> bool:
        with NamedTemporaryFile(delete=False) as input_file:
            input_file.write(prog_input.data)
            input_file.close()

            with WorkDirContext(self._runner_path.parent):
                try:
                    proc = run(["./run.sh", "run", input_file.name], capture_output=True, check=True)
                    crash = False
                except CalledProcessError as e:
                    crash = True

        return crash

    def check_functionality(self) -> ProgramExitType:
        return ProgramExitType.NORMAL


class SimpleProgramInfo(ProgramInfo):
    def __init__(self, run_script_path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executor = SimpleExecutor(run_script_path)
        self._runner_path = Path(run_script_path).resolve().absolute()

    def _compile_core(self, patch_path: Optional[Path] = None):
        if patch_path is not None:
            patch_path = Path(patch_path).absolute()
        with WorkDirContext(self._runner_path.parent):
            compile_cmd = f"./run.sh build "
            if patch_path is not None:
                compile_cmd += f"{patch_path}"
            failed = False
            try:
                proc = subprocess.run(compile_cmd.split(), capture_output=True, text=True)
            except Exception as e:
                failed = True
            if failed:
                repo = git.Repo(self.source_root)
                repo.git.reset("--hard")
                return False, f"Compilation failed: {e}"
            else:
                return proc.returncode == 0, proc.stdout


#
# Tests
#


class TestPatcheryCore(unittest.TestCase):
    def setUp(self):
        setup_testcase()

    def tearDown(self):
        teardown_testcase()

    def test_cli(self):
        # Verifies that the package has no install errors and that the CLI can be run.

        output = subprocess.run(["patchery", "--version"], capture_output=True)
        version = output.stdout.decode().strip()
        assert version == patchery.__version__

    def test_patch_diffing(self):
        # This test verifies that after an agent has generated a full function patch for a targeted function in a file,
        # that we can create a valid AIxCC patch from it, which is a Git diff.

        source_root = TARGETS / "adams"
        target_file = source_root / "main.c"
        poi = ProgramPOI(target_file, "handle_AUTH", 2689)
        prog_info = ProgramInfo(source_root=source_root, lang="C")

        # generate the perfect patch based on stored patches. This will usually come in as a string from
        # an AI agent, but for this we are just using the source code and a pre-computed patch.
        perfect_patch = Patch(
            poi,
            patch_func_from_patch_file(
                source_root, target_file, "handle_AUTH", PATCHES / "adams_good.patch", lang=prog_info.lang
            ),
            reasoning="Perfect patch.",
        )
        generated_patch_diff = prog_info.git_diff(perfect_patch)

        # confirm our generated patch is the same as the stored patch
        with open(PATCHES / "adams_good.patch", "r") as f:
            stored_patch_diff = f.read()
            assert generated_patch_diff == stored_patch_diff

        # actually apply the patch file like AIxCC would, it should not crash
        with tempfile.NamedTemporaryFile(delete=True) as temp_patch:
            temp_patch.write(generated_patch_diff.encode())
            temp_patch.seek(0)

            proc = subprocess.run(["git", "-C", str(source_root), "apply", temp_patch.name], cwd=GENERIC_TEST_DIR)
            assert proc.returncode == 0

    def test_valid_patch_compile(self):
        source_root = TARGETS / "hamlin/challenge/src"
        target_file = source_root / "src/deflate/array_history.cpp"
        poi = ProgramPOI(target_file, "ArrayHistory::copy", 26)
        prog_info = SimpleProgramInfo(
            TARGETS / "hamlin/challenge/run.sh",
            source_root=source_root,
            lang="C++",
        )

        # load a pre-computed perfect patch
        perfect_patch = Patch(
            poi,
            patch_func_from_patch_file(
                source_root, target_file, "ArrayHistory::copy", PATCHES / "hamlin_good.patch", lang=prog_info.lang
            ),
            reasoning="Perfect patch.",
        )

        # directly call the compile checker in verified
        comp_pass = CompileVerificationPass(prog_info, perfect_patch)
        comp_pass.verify()
        assert comp_pass.verified is True, comp_pass.reasoning

    def test_alert_generation(self):
        hamlin_chall = TARGETS / "hamlin/challenge"
        source_root = TARGETS / "hamlin/challenge/src"
        prog_info = SimpleProgramInfo(hamlin_chall / "run.sh", source_root=source_root, lang="C++")
        # create a binary for execution
        compiled, _ = prog_info.compile()
        if not compiled:
            raise RuntimeError("Could not compile the target binary")

        # load a benign input and an alerting input
        with open(TARGETS / "hamlin/alerting_inputs/crash_input", "rb") as f:
            alerting_input = f.read()
        benign_input = b"benign"

        assert prog_info.tiggers_alert(ProgramInput(alerting_input, ProgramInputType.FILE)) is True
        assert prog_info.tiggers_alert(ProgramInput(benign_input, ProgramInputType.FILE)) is False

    def test_end_to_end_hamlin(self):
        source_root = TARGETS / "hamlin/challenge/src"
        poi = ProgramPOI(
            source_root / "src/deflate/array_history.cpp",
            "ArrayHistory::copy",
            26,
            report="There is a buffer overflow in this function.",
        )
        prog_info = SimpleProgramInfo(
            TARGETS / "hamlin/challenge/run.sh",
            source_root=source_root,
            alerting_inputs=AICCProgramInfo.load_inputs_from_dir(TARGETS / "hamlin/alerting_inputs"),
            lang="C++",
        )

        # validate hamlin is broke for real before we start, so we compile a non-patched version
        compiled, _ = prog_info.compile()
        assert compiled is True
        env = os.environ.copy()
        env["CHESS"] = "1"
        hamlin_bin = TARGETS / "hamlin/challenge/hamlin.bin"
        with open(TARGETS / "hamlin/alerting_inputs/crash_input", "rb") as f:
            crashing_input = f.read()
        proc = subprocess.run([hamlin_bin], capture_output=True, input=crashing_input, env=env, text=False)
        assert b"ERROR: AddressSanitizer" in proc.stderr

        patcher = Patcher(prog_info, max_patches=1, max_attempts=5)
        verified_patches = patcher.generate_verified_patches(pois=[poi], report=poi.report)
        assert bool(verified_patches)

        verified_patch = verified_patches[0]
        prog_info.compile(verified_patch)
        # validate the patch actually fixed the issue
        proc = subprocess.run([hamlin_bin], capture_output=True, input=crashing_input, env=env, text=False)
        assert b"ERROR: AddressSanitizer" not in proc.stderr

    @unittest.skip("this needs to be moved to the AIxCC tests")
    def test_end_to_end_hamlin_cli(self):
        tests = GENERIC_TEST_DIR.absolute()
        with tempfile.NamedTemporaryFile(delete=True) as f:
            f.seek(0)
            file_path = Path(f.name).absolute()

            full_command = textwrap.dedent(
                f"""
            patchery --generate-verified-patch
                --src-root {tests}/targets/hamlin/challenge/src/
                --run-script {tests}/targets/hamlin/challenge/run.sh
                --lang C++
                --report-file {tests}/reports/hamlin_report.txt
                --poi-file {tests}/targets/hamlin/challenge/src/src/deflate/array_history.cpp
                --poi-func ArrayHistory::copy
                --poi-line 26
                --benign-inputs {tests}/targets/hamlin/benign_inputs/
                --alerting-inputs {tests}/targets/hamlin/alerting_inputs/
                --harness-id ""
                --compile-name src
                --output-path {file_path}
            """
            )
            # split the command into individual commands
            commands = []
            for cmd in full_command.split("\n"):
                if not cmd:
                    continue

                split_cmds = cmd.split(" ")
                for scmd in split_cmds:
                    if scmd:
                        commands.append(scmd)

            proc = subprocess.run(commands)
            assert proc.returncode == 0

            # check that real content was written to the file
            with open(file_path, "r") as f:
                diff_data = f.read()

            assert diff_data
            assert diff_data.startswith("diff --git")
            # a guesstimate that the patch has real changes
            assert len(diff_data.split("\n")) > 10

    @unittest.skip("Does not work while clang_indexer is disabled")
    def test_code_parsing(self):
        target_file = TARGETS / "hamlin/challenge/src/src/deflate/array_history.cpp"
        parser = CodeParser(target_file)
        parser.parse()

        # verify that we can get the code for a function
        assert "ArrayHistory::copy" in parser.functions
        assert "ArrayHistory::append" in parser.functions
        assert "ArrayHistory::ArrayHistory" in parser.functions

        func = parser.functions["ArrayHistory::copy"]
        assert func.start_line == 17
        assert func.end_line == 34


if __name__ == "__main__":
    unittest.main(argv=sys.argv, buffer=True)
