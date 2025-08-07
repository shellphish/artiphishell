# load `div_lib.so` and call the real divb function

from ctypes import *
import random
import struct
import sys

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

divb.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
divb.restype = c_int
divw.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
divw.restype = c_int
divl.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
divl.restype = c_int
divq.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
divq.restype = c_int

idivb.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
idivb.restype = c_int
idivw.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
idivw.restype = c_int
idivl.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
idivl.restype = c_int
idivq.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
idivq.restype = c_int

def do_divb(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divb(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivb(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divb(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divw(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divw(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivw(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivw(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divl(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divl(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivl(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivl(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_divq(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = divq(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

def do_idivq(a, b):
    quot = c_ulong(0)
    rem = c_ulong(0)
    status = idivq(a, b, byref(quot), byref(rem))
    return status, quot.value, rem.value

res = {}
seen_outs = set()
for ax in range(0, 0x1000):
    for j in range(0, 0x100):
        rand_high_numerator = random.randint(0, (1 << 48)-1) << 16
        rand_high_denominator = random.randint(0, (1 << 56)-1) << 8

        # if ax / j > 0xff:
        #     continue

        cur_ax = ax | rand_high_numerator
        cur_j = j | rand_high_denominator

        out = do_divb(cur_ax, cur_j)
        if out in seen_outs:
            continue
        seen_outs.add(out)

        if cur_ax % 0x1000 == 0:
            # if cur_ax == 0xfbfffbfffff70000:
            #     import ipdb; ipdb.set_trace()
            print(hex(cur_ax), hex(cur_j))
        res[(cur_ax, cur_j)] = out


reversed = {(status, q, r): (a, b) for (a, b), (status, q, r) in res.items() }

text = """
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "div_lib.h"

int main() {{
    u_int64_t buf[{}];
    unsigned long quot, rem, numerator, denominator;
    read(0, buf, sizeof(buf));
""".format(len(reversed) * 2)

input = []
for i, ((status, quotient, remainder), (numerator,denominator)) in enumerate(reversed.items()):
    text += f"""
    quot = 0;
    rem = 0;
    numerator = buf[{i*2}];
    denominator = buf[{i*2+1}];

    if(numerator != {hex(numerator)}ul || denominator != {hex(denominator)}ul) {{
        printf("Wrong input for check {i}, expected {hex(numerator)} / {hex(denominator)}, got 0x%lx / 0x%lx\\n", numerator, denominator);
        return 1;
    }}
    divb(numerator, denominator, &quot, &rem);
    if (quot != {hex(quotient)}ul || rem != {hex(remainder)}ul) {{
        printf("Wrong result for check {i}, expected quotient=={hex(quotient)} and remainder=={hex(remainder)}, got %lx / %lx\\n", quot, rem);
        abort();
    }}
    printf("Passed check #{i}!\\n");
"""
    input += [(numerator, denominator)]

text += """
    puts("OK");
    return 0;
}
"""
with open('tester.c', 'w') as f:
    f.write(text)

with open('full_input', 'wb') as f:
    for numerator, denominator in input:
        f.write(struct.pack("<QQ", numerator, denominator))