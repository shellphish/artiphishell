from pathlib import Path

import pytest
import subprocess
from debug_lib.debuggers import GDBDebugger

DEBUG_FOLDER = Path(__file__).absolute().parent / "programs"


def get_debug_program(folder):
    debug_program = DEBUG_FOLDER / folder / "program.debug"
    if not debug_program.exists():
        subprocess.run(["make"], cwd=DEBUG_FOLDER)
    return debug_program


@pytest.fixture
def base_debugger():
    return GDBDebugger(program=get_debug_program("base"))


@pytest.fixture
def overflow_debugger():
    return GDBDebugger(program=get_debug_program("buffer_overflow"), argv=["arg1", "arg2"], stdin=b"input")


@pytest.fixture
def mock_cp_debugger():
    inp = b"A" * 8 + b"\n" + b"\x00"  # Func A inp
    inp += b"0"  # Func B inp
    return GDBDebugger(program=get_debug_program("mock-cp"), stdin=b"0\n")


@pytest.fixture
def tcache_debugger():
    return GDBDebugger(program=get_debug_program("tcache"), argv=["arg1", "arg2"], stdin=b"input")


# def test_remote():
#     HOST = 'localhost'
#     PORT = 1234
#     proc = subprocess.Popen(["gdbserver", "--multi", f"{HOST}:{PORT}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     try:
#         gdb_debugger = GDBDebugger(program=get_debug_program("buffer_overflow"), argv=["arg1", "arg2"], stdin=b'input', remote=f"{HOST}:{PORT}")
#         gdb_debugger.run()
#         assert len(gdb_debugger.context.backtrace.bt) == 7
#     except Exception as e:
#         proc.poll()
#         proc.kill()
#         proc.wait()
#         raise e


def test_run(base_debugger: GDBDebugger):
    base_debugger.run()
    assert base_debugger.stdout[0] == "Hello, World!"
    base_debugger.quit()


def test_set_breakpoint_by_function(base_debugger: GDBDebugger):
    base_debugger.set_breakpoint(function="main")
    base_debugger.run()
    assert len(base_debugger.breakpoints) == 1
    assert base_debugger.frame.function == "main"

    base_debugger.remove_breakpoint(base_debugger.breakpoints[-1])
    base_debugger.run()
    assert len(base_debugger.breakpoints) == 0
    assert base_debugger.frame.function is None
    assert base_debugger.stdout[0] == "Hello, World!"
    base_debugger.quit()


def test_continue_execution(base_debugger: GDBDebugger):
    base_debugger.set_breakpoint(function="main")
    base_debugger.run()
    base_debugger.continue_execution()
    assert base_debugger.stdout[0] == "Hello, World!"
    base_debugger.quit()


def test_finish(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(function="func_a")
    mock_cp_debugger.run()
    assert mock_cp_debugger.frame.function == "func_a"

    mock_cp_debugger.finish()
    assert mock_cp_debugger.frame.function == "main"
    mock_cp_debugger.quit()


def test_step(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(file="program.c", line=34)
    mock_cp_debugger.run()
    assert mock_cp_debugger.frame.function == "main" and mock_cp_debugger.frame.line == 34
    mock_cp_debugger.step()
    assert mock_cp_debugger.frame.function == "func_a" and mock_cp_debugger.frame.line == 9
    mock_cp_debugger.quit()


def test_next(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(file="program.c", line=34)
    mock_cp_debugger.run()
    assert mock_cp_debugger.frame.function == "main" and mock_cp_debugger.frame.line == 34
    mock_cp_debugger.next()
    assert mock_cp_debugger.frame.function == "main" and mock_cp_debugger.frame.line == 36
    mock_cp_debugger.quit()


def test_backtrace_navigation(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(function="func_a")
    mock_cp_debugger.run()

    assert len(mock_cp_debugger.backtrace) == 2
    assert mock_cp_debugger.frame.function == "func_a"
    assert mock_cp_debugger.frame.depth == 0

    mock_cp_debugger.up()
    assert len(mock_cp_debugger.backtrace) == 2
    assert mock_cp_debugger.frame.function == "main"
    assert mock_cp_debugger.frame.depth == 1

    mock_cp_debugger.down()
    assert len(mock_cp_debugger.backtrace) == 2
    assert mock_cp_debugger.frame.function == "func_a"
    assert mock_cp_debugger.frame.depth == 0
    mock_cp_debugger.quit()


def test_locals(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(file="program.c", line=15)
    mock_cp_debugger.run()
    assert len(mock_cp_debugger.local_variables) == 2

    var_dict = {"buff": {"value": '"0\\n"', "type": "char *"}, "i": {"value": "1", "type": "int"}}
    for var in mock_cp_debugger.local_variables:
        assert var.name in var_dict
        assert var_dict[var.name]["value"] == var.value and var_dict[var.name]["type"] == var.type
    mock_cp_debugger.quit()


def test_register_info(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.set_breakpoint(file="program.c", line=9)
    mock_cp_debugger.run()

    mock_cp_debugger.next_insn()
    mock_cp_debugger.next_insn()
    changed_registers = {x.name: x for x in mock_cp_debugger.registers.values() if x.changed}
    assert len(changed_registers) == 2
    assert "rip" in changed_registers and "rax" in changed_registers
    mock_cp_debugger.quit()


def test_globals(mock_cp_debugger: GDBDebugger):
    mock_cp_debugger.track_global("items")
    mock_cp_debugger.set_breakpoint(function="func_b")
    mock_cp_debugger.run()
    assert len(mock_cp_debugger.global_variables) == 1
    assert mock_cp_debugger.global_variables[0].name == "items"
