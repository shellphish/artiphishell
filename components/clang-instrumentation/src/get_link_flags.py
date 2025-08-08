import os
import sys
import json
import subprocess

if len(sys.argv) != 4:
    print("Usage: python get_link_flags.py <link_commands.json> <bitcode_file_name> <output_file>")
    sys.exit(1)

IGNORE_LIST = ["/usr/bin/ld", "-o", "ld", "-lFuzzingEngine"]
APPEND_LIST = ["-lasan"]

link_commands_file = sys.argv[1]
bitcode_file_name = sys.argv[2][:-3] if sys.argv[2].endswith(".bc") else sys.argv[2]
output_file = sys.argv[3]
assert os.path.exists(link_commands_file), f"File {link_commands_file} does not exist."

if os.path.exists(output_file):
    os.remove(output_file)

with open(link_commands_file, 'r') as f:
    link_commands = json.load(f)

link_flags = []

args = []
inputs = []
for command in link_commands:
    if os.path.basename(command["output"]) == bitcode_file_name:
        args = command.get('arguments', [])
        inputs = command.get('input_files', [])
        break

i = 0
while i < len(args):
    arg = args[i]

    if arg == "-o":
        i += 2
        continue
    if arg in IGNORE_LIST or arg in inputs or arg.endswith(".o") or arg.endswith(".a"):
        i += 1
        continue

    if arg.startswith("-L") or arg.startswith("-l"):
        link_flags.append(arg)
        i += 1
        continue

    if arg.startswith("-") and (i + 1 < len(args)):
        next_arg = args[i + 1]
        if not next_arg.startswith("-"):
            link_flags.append(f"-Wl,{arg},{next_arg}")
            i += 2
            continue

    if arg.startswith("-") or arg.startswith("--"):
        link_flags.append(f"-Wl,{arg}")
    else:
        link_flags.append(arg)

    i += 1

link_flags+= APPEND_LIST

print(" ".join(link_flags))
with open(output_file, 'w') as f:
    f.write(" ".join(link_flags))