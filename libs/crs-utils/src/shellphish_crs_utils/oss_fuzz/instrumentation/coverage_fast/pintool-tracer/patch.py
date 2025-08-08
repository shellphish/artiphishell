#!/usr/bin/env python3

import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

import subprocess
from keystone import *
if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + " <binary> [<output>]")
    exit(1)
    
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# # CHECK ASAN 
# cmd = "nm -C " + sys.argv[1] + " | grep -i asan"
# print("DEBUG: " + cmd)
# p = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True)

def find_inlined_sites(binary_path, symbol_name):
    FUNCTION_TAG="DW_TAG_subprogram"
    INLINED_TAG="DW_TAG_inlined_subroutine"

    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF info found.")
            exit(1)
        
        symbol_die_off = 0x0
        symbol_cu = None

        dwarf_info = elf.get_dwarf_info()
        ret = {f"{symbol_name}": []} # this is gonna include all the tuples with the inlined sites

        cu_num = 0
        for c in dwarf_info.iter_CUs():
            cu_num += 1
        
        print(f"[+] Searching {cu_num} CUs for function: {symbol_name}")
        
        for i, CU in enumerate(dwarf_info.iter_CUs()):
            print(f"DEBUG: CU {i}/{cu_num} {str(CU)}")
            
            for die in CU.iter_DIEs():
                if die.tag == FUNCTION_TAG:
                    proc_name = die.attributes.get('DW_AT_name')
                    
                    if proc_name:
                        # WATCH OUT: exact symbol name
                        if symbol_name == proc_name.value.decode('utf-8'):
                            print("Found function: " + proc_name.value.decode('utf-8'), " at offset: " + hex(die.offset))
                            symbol_die_off = die.offset # name is gonna be at offset+1
                            symbol_cu = CU
                            
                
                elif die.tag == INLINED_TAG:
                    origin = die.attributes.get('DW_AT_abstract_origin')
                    offset = origin.value + CU.cu_offset

                    if offset == symbol_die_off:
                        print("Found inlined site at offset: " + hex(die.offset))
                        inline = (die.attributes["DW_AT_low_pc"].value, die.attributes["DW_AT_low_pc"].value + die.attributes["DW_AT_high_pc"].value)
                        ret[f"{symbol_name}"].append(inline)
                        return ret # TODO: remove this in the final version
    
    return ret
                        



# find StartRssThread in the binary
import time
now = time.time()
inlines = find_inlined_sites(sys.argv[1], 'StartRssThread')
assert len(inlines["StartRssThread"]) == 1 # we assume this is inlined once
end = time.time()
print(f"DEBUG: {len(inlines)}, elapsed: {end-now}")

# find __asan::CreateMainThread in the binary
# cmd = "nm -C " + sys.argv[1] + " | grep __asan::CreateMainThread"
# print("DEBUG: " + cmd)
# p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
# p.wait()
# output = p.stdout.read().decode('utf-8').split(" ")[0]
# assert output != ""
# asanCreateMainThread = int(output, 16)

# create patch to StartRssThread
offset_to_rssthread_start = inlines['StartRssThread'][0][0] 
offset_to_rssthread_end = inlines['StartRssThread'][0][1]
len_rssthread = offset_to_rssthread_end - offset_to_rssthread_start
NopSled = ks.asm("nop")[0] * len_rssthread
print("DEBUG: offset to StartRssThread: " + hex(offset_to_rssthread_start), "len: " + hex(len_rssthread), "nop sled: " + hex(len(NopSled)))

# create patch to the callsite of __asan::CreateMainThread
# objdump_path = subprocess.check_output(["find", "/usr/bin", "-name","llvm-objdump*"]).decode('utf-8').strip()
# objdump_path = "objdump"
# import os 
# harness = sys.argv[1]
# dump_path = harness +".asm"
# p = subprocess.Popen([objdump_path, "-d", harness ], stdout=open(dump_path, "w"))
# p.wait()
# if p.returncode != 0:
#     print("Error: objdump failed")
#     exit(1)

# cmd = "grep -A 10 call.*" + hex(asanCreateMainThread).replace("0x", "") + " " + dump_path
# print("DEBUG: " + cmd)
# q = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
# q.wait()
# if q.returncode != 0:
#     print("Error: grep failed")
#     exit(1)

# lines = q.stdout.readlines()
# first = int(lines[0].decode('utf-8').split(":")[0].strip(), 16) 


# for i in range(1, len(lines)):
#     if "call" in lines[i].decode('utf-8').strip():
#         last = int(lines[i].decode('utf-8').split(":")[0].strip(), 16) 
#         break

# print(f"DEBUG: {hex(first)} {hex(last)}") # [83a5ce, 83a5df)
# nop, count = ks.asm("nop") # DON'T put ; at the end of the line
# try: 
#     xorRaxRax, count = ks.asm("xor rax, rax")
#     XorRaxRaxNops = xorRaxRax + nop * (last-first-len(xorRaxRax))
# except Exception as e:
#     print(f"Error: {e}")
    
#     exit(1)

# assert len(XorRaxRaxNops) == last-first
# print(f"DEBUG: offsets for callsite of __asan::CreateMainThread: {hex(first)} {hex(last)}")

# patch asan_create_main_thread
content = b""


with open(sys.argv[1], 'rb') as f:
    content = bytearray(f.read())
    
    for i in range(len(NopSled)):
        content[offset_to_rssthread_start+i] = NopSled[i]

patched_file = sys.argv[2] if len(sys.argv) > 2 else sys.argv[1] + ".patched"
with open(patched_file, 'wb') as f:
    f.write(content)

print("Patched file created: " + patched_file)
# import shutil
# import os
# shutil.unlink(patched_file + ".asm")
# os.remove(patched_file + ".asm")
subprocess.run(["chmod", "+x", patched_file])
