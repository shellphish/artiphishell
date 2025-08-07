import pprint
from pathlib import Path

from universal_dbg.debuggers import JavaDebugger



if __name__ == '__main__':
    cur_dir  = Path(__file__).absolute().parent
    gdb = JavaDebugger("HelloWorld", class_path=cur_dir / "test.jar", source_path=cur_dir, argv=["1", "2"])
    gdb.set_breakpoint("HelloWorld:3")
    gdb.run()
    gdb.print_context()
    for i in range(15):
        gdb.print_context()
        gdb.next()
    gdb.continue_execution()
    print("\n".join(gdb.stdout))