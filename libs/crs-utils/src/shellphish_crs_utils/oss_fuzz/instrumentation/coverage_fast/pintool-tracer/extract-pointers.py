#!/usr/bin/env python3

import re
import sys
#  0x00067f8c: DW_TAG_inlined_subroutine DW_AT_abstract_origin	(0x00067f7b "ngx_get_options") DW_AT_ranges	(indexed (0x0) rangelist = 0x0001b633 [0x00000000001016fd, 0x0000000000101dfe) [0x0000000000101f16, 0x0000000000101f4f) [0x00000000001021f8, 0x0000000000102231) [0x0000000000102247, 0x000000000010225f)) DW_AT_call_file	("/src/harnesses/bld/src/core/nginx.c") DW_AT_call_line	(225) DW_AT_call_column	(9)

def extract_function_pointer_ranges(lines):
    results = []
    pattern = re.compile(r'\[(0x[a-f0-9]+),')
    
    for line in lines:
        # parts = line.split('"')
        # name = parts[1]
        match = pattern.findall(line)
        
        # 
        # filename = line.split("DW_AT_call_file")[1].split('("')[1].split('")')[0]
        assert len(match) > 0
        for m in match:
            address = m
            results.append(f"{address}") # {name} {filename}")
    
    return results

def extract_function_pointer(lines):
    results = []
    pattern = re.compile(r'DW_AT_low_pc\s+\((0x[a-f0-9]+)\)')
    
    for line in lines:
        # parts = line.split('"')
        # name = parts[1]
        match = pattern.findall(line)
        # filename = line.split("DW_AT_call_file")[1].split('("')[1].split('")')[0]
        assert len(match) > 0
        for m in match:
            address = m
            # print(address)
            results.append(f"{address}") #  {name} {filename}")
                
    
    return results



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <input_file_ranges> <input_file_no_ranges>")
        sys.exit(1)
    
    input_file_ranges = sys.argv[1]
    input_file_no_ranges = sys.argv[2]
    
    # assert "nonranges" not in input_file_ranges
    
    with open(input_file_ranges, 'r') as f:
        ranges_lines = f.readlines()
    with open(input_file_no_ranges, 'r') as f:
        no_ranges_lines = f.readlines()
    # print("DEBUG: length of ranges_lines", len(ranges_lines))
    # print("DEBUG: length of no_ranges_lines", len(no_ranges_lines))
    
    output = extract_function_pointer(no_ranges_lines)
    output += extract_function_pointer_ranges(ranges_lines)
    # remove duplicates
    output = list(set(output))
    output.sort()
    
    for line in output:
        print(line)