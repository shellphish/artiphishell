#!/bin/bash

# Set the path to the Python script.
SCRIPT_PATH="work/script.py"

# Print the script.
cat "$SCRIPT_PATH"

echo "Running the script... in sh"
# Run it using Python.
timeout 60 python3 "$SCRIPT_PATH" "$@"

if [ -f /work/crash.txt ] && [ $(stat -c%s /work/crash.txt) -gt 2097152 ]; then
    truncate -s 2M /work/crash.txt
fi
