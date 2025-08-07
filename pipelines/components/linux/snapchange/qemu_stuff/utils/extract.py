import sys

vm_log_path = sys.argv[1]
with open(vm_log_path) as fp:
    vm_log = fp.read()

gdb_symbols = vm_log.split("===== GDB SYMBOLS START =====")[1].split("====== GDB SYMBOLS END ======")[0]
gdb_modules = vm_log.split("===== GDB MODULES START =====")[1].split("====== GDB MODULES END ======")[0]
gdb_vmmap   = vm_log.split("====== GDB VMMAP START ======")[1].split("======= GDB VMMAP END =======")[0]

with open("./gdb.symbols", "w+") as fp:
    fp.write(gdb_symbols)

with open("./gdb.modules", "w+") as fp:
    fp.write(gdb_modules)

with open("./gdb.vmmap", "w+") as fp:
    fp.write(gdb_vmmap)

print("extract.py: DONE!")
