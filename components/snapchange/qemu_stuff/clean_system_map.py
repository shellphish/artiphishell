import sys

def parse_kallsyms(data):
    ''' Parse the /proc/kallsyms output and return the symbol addresses '''
    out = ""

    for line in data.split('\n'):
        # Ignore (addr, __key*) line
        if '__key' in line:
             continue

        # Example line
        # ffffffffc0b2bb50 t btrfs_calculate_inode_block_rsv_size	[btrfs]
        line = line.split()
        if len(line) < 2:
            continue

        # Add the symbol address and symbol name to the symbols database
        addr = int(line[0], 16)
        out += f"{hex(addr)} {line[2]}\n"
    return out

def usage():
    print("clean_system_map.py <system_map_file> <output_path>")
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) <= 2: usage()

    with open(sys.argv[1], "r") as system_map_fp:
        system_map = system_map_fp.read()

    parsed = parse_kallsyms(system_map)

    with open(sys.argv[2], "w+") as out_fp:
        out_fp.write(parsed)
