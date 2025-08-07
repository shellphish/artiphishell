# Description: This script is a proof of concept that Fabio is a genius
import psutil
from pwn import *
import time

timeout_processes = []
for proc in psutil.process_iter():
    if proc.name() == "timeout":
        timeout_processes.append(proc)

print(timeout_processes)

def demonstrate_fabios_genius(pid, seconds_to_add):
    pid, g = gdb.attach(pid, api=True)
    stack_base = int([l.strip().split()[0] for l in g.execute('info proc mappings', to_string=True).split('\n') if 'stack' in l][0], base=16)

    g.execute(f'set *(unsigned long long){hex(stack_base)} = 0x0')
    gettime_res = g.execute(f'p timer_gettime({hex(stack_base)}, {hex(stack_base + 8)})', to_string=True)
    assert('0x0' in gettime_res)
    print(f'gettime_res: {gettime_res!r}')
    print(g.execute(f'x/gx {hex(stack_base+0x18)}', to_string=True))
    if seconds_to_add == 0:
        g.execute('c')
        return
    if seconds_to_add < 0:
        seconds_to_add = -seconds_to_add
        g.execute(f'set *(unsigned long long){hex(stack_base + 0x18)} -= {seconds_to_add}')
    else:
        g.execute(f'set *(unsigned long long){hex(stack_base + 0x18)} += {seconds_to_add}')

    res_settime = g.execute(f'p timer_settime({hex(stack_base)}, 0, {hex(stack_base + 8)}, {hex(stack_base + 8)})', to_string=True)
    g.execute('c')

#for p in timeout_processes:
#    demonstrate_fabios_genius(p.pid, 60 * 60 * 24 * 5)
    # break

for pid in timeout_processes:
    demonstrate_fabios_genius(pid.pid, 5 * 24 * 60 * 60)
    time.sleep(1)

