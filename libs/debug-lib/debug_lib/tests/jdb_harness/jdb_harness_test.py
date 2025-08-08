from pathlib import Path

import pytest
from debug_lib.debuggers import JavaDebugger


def get_debug_program(folder):
    return Path(__file__).absolute().parent / "programs" / folder / "program.debug.jar"


@pytest.fixture
def base_debugger():
    debug_prog = get_debug_program("base")
    return JavaDebugger(debug_class="Program", class_path=debug_prog, source_path=debug_prog.parent, argv=["1", "2"])


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


def test_run(base_debugger: JavaDebugger):
    base_debugger.run()
    assert base_debugger.stdout[3] == "Hello World!"
    base_debugger.quit()


def test_set_breakpoint_by_function(base_debugger: JavaDebugger):
    base_debugger.set_breakpoint(function="Program.main")
    base_debugger.run()
    assert len(base_debugger.breakpoints) == 1
    assert base_debugger.frame.function == "main"

    base_debugger.remove_breakpoint(base_debugger.breakpoints[-1])
    base_debugger.run()
    assert len(base_debugger.breakpoints) == 0
    assert base_debugger.frame.function is None
    assert base_debugger.stdout[3] == "Hello World!"
    base_debugger.quit()


def test_continue_execution(base_debugger: JavaDebugger):
    base_debugger.set_breakpoint(function="Program.main")
    base_debugger.run()
    base_debugger.continue_execution()
    assert base_debugger.stdout[3] == "Hello World!"
    base_debugger.quit()


# def test_finish(mock_cp_debugger: GDBDebugger):
# mock_cp_debugger.set_breakpoint(function="func_a")
# mock_cp_debugger.run()
# assert mock_cp_debugger.frame.function == "func_a"
#
# mock_cp_debugger.finish()
# assert mock_cp_debugger.frame.function == "main"
# mock_cp_debugger.quit()
#
#
def test_step(base_debugger: JavaDebugger):
    base_debugger.set_breakpoint(class_name="Program", line=21)
    base_debugger.run()
    assert base_debugger.frame.function == "main" and base_debugger.frame.line == 21
    base_debugger.step()
    assert base_debugger.frame.function == "innerFunction" and base_debugger.frame.line == 6
    base_debugger.quit()


def test_next(base_debugger: JavaDebugger):
    base_debugger.set_breakpoint(function="Program.main")
    base_debugger.run()
    assert base_debugger.frame.function == "main" and base_debugger.frame.line == 19
    base_debugger.next()
    assert base_debugger.frame.function == "main" and base_debugger.frame.line == 20
    base_debugger.quit()


# def test_backtrace_navigation(base_debugger: JavaDebugger):
# base_debugger.set_breakpoint(function="Program.innerFunction")
# base_debugger.run()
# assert len(base_debugger.backtrace) == 2
# assert base_debugger.frame.function == "innerFunction"
#
# base_debugger.up()
# assert len(base_debugger.backtrace) == 2
# assert base_debugger.frame.function == "main"
#
# base_debugger.down()
# assert len(base_debugger.backtrace) == 2
# assert base_debugger.frame.function == "innerFunction"
# base_debugger.quit()


def test_locals(base_debugger: JavaDebugger):
    base_debugger.set_breakpoint(class_name="Program", line=15)
    base_debugger.run()
    assert len(base_debugger.local_variables) == 4

    var_dict = {
        "o": {"value": "{}", "type": "java.lang.Object"},
        "a": {"value": "1", "type": "int"},
        "b": {"value": "2", "type": "int"},
        "c": {"value": "3", "type": "int"},
    }
    for var in base_debugger.local_variables:
        assert var.name in var_dict
        assert var_dict[var.name]["value"] == var.value and var_dict[var.name]["type"] == var.type
    base_debugger.quit()


# def test_register_info(mock_cp_debugger: GDBDebugger):
# mock_cp_debugger.set_breakpoint(file="program.c", line=9)
# mock_cp_debugger.run()
#
# mock_cp_debugger.next_insn()
# mock_cp_debugger.next_insn()
# changed_registers = {x.name: x for x in mock_cp_debugger.registers.values() if x.changed}
# assert len(changed_registers) == 2
# assert "rip" in changed_registers and "rax" in changed_registers
# mock_cp_debugger.quit()
#
#
# def test_globals(mock_cp_debugger: GDBDebugger):
# mock_cp_debugger.track_global("items")
# mock_cp_debugger.set_breakpoint(function="func_b")
# mock_cp_debugger.run()
# assert len(mock_cp_debugger.globals) == 1
# assert mock_cp_debugger.globals[0].name == "items"
#
