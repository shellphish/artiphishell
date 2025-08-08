import subprocess
import sys
import os
import re

def library_exists(libname):
    try:
        output = subprocess.check_output(["ldconfig", "-p"], text=True)
        pattern = re.compile(rf'\s+lib{re.escape(libname)}\.so(\.\d+)*\s')
        return any(pattern.search(line) for line in output.splitlines())
    except Exception as e:
        print(f"Warning: Could not check for library '{libname}': {e}")
        return False

if len(sys.argv) != 2:
    print("Usage: python fix_link_flags.py <link_commands_file>")
    sys.exit(1)

link_commands_file = sys.argv[1]
if not os.path.exists(link_commands_file):
    print(f"File {link_commands_file} does not exist.")
    sys.exit(0)

with open(link_commands_file, 'r') as f:
    flags = f.read().split()

filtered_flags = []
for flag in flags:
    if flag.startswith("-l"):
        libname = flag[2:]
        if "++" in libname or library_exists(libname):
            filtered_flags.append(flag)
        else:
            print(f"Warning: Library '{libname}' not found. Skipping flag '{flag}'")
    else:
        filtered_flags.append(flag)

with open(link_commands_file, 'w') as f:
    f.write(" ".join(filtered_flags))
