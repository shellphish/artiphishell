# Description: This script is a proof of concept that Fabio is a genius
import psutil
from pwn import *

timeout_processes = []
for proc in psutil.process_iter():
    if proc.name() == "timeout":
        timeout_processes.append(proc)

print(timeout_processes)

def demonstrate_fabios_genius(process, seconds_to_add):
    pid, g = gdb.attach(process.pid, api=True)
    stack_base = int([l.strip().split()[0] for l in g.execute('info proc mappings', to_string=True).split('\n') if 'stack' in l][0], base=16)

    g.execute(f'set *(unsigned long long){hex(stack_base)} = 0x0')
    gettime_res = g.execute(f'p timer_gettime({hex(stack_base)}, {hex(stack_base + 8)})', to_string=True)
    assert('0x0' in gettime_res)
    print(f'gettime_res: {gettime_res!r}')
    g.execute(f'set *(unsigned long long){hex(stack_base + 0x18)} += {seconds_to_add}')

    res_settime = g.execute(f'p timer_settime({hex(stack_base)}, 0, {hex(stack_base + 8)}, {hex(stack_base + 8)})', to_string=True)
    assert('0x0' in res_settime)
    g.execute('c')

for p in timeout_processes:
    demonstrate_fabios_genius(p, 60)
    # break

