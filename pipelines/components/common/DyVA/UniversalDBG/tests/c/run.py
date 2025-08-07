import pprint
from pathlib import Path

from universal_dbg.debuggers import GDBDebugger

if __name__ == '__main__':
    cur_dir  = Path(__file__).absolute().parent
    gdb = GDBDebugger(cur_dir  / "test.debug", stdin=b"1 2\n")
    gdb.set_breakpoint("main")
    gdb.set_breakpoint("main")
    gdb.set_breakpoint("main")
    gdb.run()
    gdb.track_global("d")
    gdb.step_insn()
    print(f"Breakpoints: {[hex(x) for x in gdb.get_breakpoint_info()]}")
    for i in range(15):
        gdb.print_context()
        gdb.next()
        gdb.print_context()
        print(f"PC: {hex(gdb.program_counter())}")
    gdb.print_context()
    gdb.continue_execution()
    print('\n'.join(gdb.stdout))
