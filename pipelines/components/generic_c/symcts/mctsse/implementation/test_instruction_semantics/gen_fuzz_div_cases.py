# load `div_lib.so` and call the real divb function

from ctypes import *
import random
import struct
import sys

div_function = sys.argv[1]
num_test_cases = int(sys.argv[2])
random.seed(1)

div_lib = cdll.LoadLibrary("./div_lib.so")

divb = div_lib.divb
divw = div_lib.divw
divl = div_lib.divl
divq = div_lib.divq

idivb = div_lib.idivb
idivw = div_lib.idivw
idivl = div_lib.idivl
idivq = div_lib.idivq

divb.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
divb.restype = c_int
divw.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
divw.restype = c_int
divl.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
divl.restype = c_int
divq.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
divq.restype = c_int

idivb.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
idivb.restype = c_int
idivw.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
idivw.restype = c_int
idivl.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
idivl.restype = c_int
idivq.argtypes = [c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
idivq.restype = c_int

def do_divb(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divb(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivb(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivb(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divw(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divw(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivw(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivw(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divl(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divl(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivl(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivl(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divq(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divq(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivq(eax, edx, denom):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivq(eax, edx, denom, byref(quot), byref(rem))
    return status, quot.value, rem.value

# import ipdb; ipdb.set_trace()
output_to_inputs = {}
while len(output_to_inputs) < num_test_cases:
    eax = random.randint(0, 0xffffffffffffffff)
    edx = random.randint(0, 0xffffffffffffffff)
    denom = random.randint(0, 0xffffffffffffffff)
    status, quot, rem = globals()['do_' + div_function](eax, edx, denom)
    output_to_inputs[(status, quot, rem)] = (eax, edx, denom)

output_to_inputs

text = """
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "div_lib.h"

int main() {{
    u_int64_t buf[{}];
    unsigned long quot, rem, pre_eax, pre_edx, denominator;
    read(0, buf, sizeof(buf));
""".format(len(output_to_inputs) * 3)

input = []
for i, ((status, quotient, remainder), (eax,edx,denominator)) in enumerate(output_to_inputs.items()):
    text += f"""
    quot = 0;
    rem = 0;
    pre_eax = buf[{i*3}];
    pre_edx = buf[{i*3+1}];
    denominator = buf[{i*3+2}];

    if(pre_eax != {hex(eax)}ul || pre_edx != {hex(edx)}ul || denominator != {hex(denominator)}ul) {{
        printf("Wrong input for check {i}, expected {hex(edx)}:{hex(eax)} / {hex(denominator)}, got 0x%lx:0x%lx / 0x%lx\\n", pre_edx, pre_eax, denominator);
        return 1;
    }}
    assert(_{div_function}(pre_eax, pre_edx, denominator, &quot, &rem) == {status});
    if (quot != {hex(quotient)}ul || rem != {hex(remainder)}ul) {{
        printf("Wrong result for check {i}, expected quotient=={hex(quotient)} and remainder=={hex(remainder)}, got %lx / %lx\\n", quot, rem);
        abort();
    }}
    printf("Passed check #{i}!\\n");
"""
    input += [(eax, edx, denominator)]

text += """
    puts("OK");
    return 0;
}
"""
with open(f'tester_fuzz_{div_function}.c', 'w') as f:
    f.write(text)

with open(f'full_input_fuzz_{div_function}', 'wb') as f:
    for eax,edx, denominator in input:
        f.write(struct.pack("<QQQ", eax, edx, denominator))