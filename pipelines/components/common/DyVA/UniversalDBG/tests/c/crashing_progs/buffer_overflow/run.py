import pprint
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).absolute().parent.parent.parent))

from universal_dbg.debuggers import GDBDebugger

if __name__ == '__main__':
    cur_dir  = Path(__file__).absolute().parent

    gdb = GDBDebugger(cur_dir  / "prog", stdin=b"1 2\n")
    gdb.set_breakpoint("main")
    gdb.run()
    gdb.step_insn()
    for i in range(15):
        gdb.print_context()
        #gdb.next()
        gdb.print_context()
    gdb.print_context()
    gdb.continue_execution()
    print('\n'.join(gdb.stdout))