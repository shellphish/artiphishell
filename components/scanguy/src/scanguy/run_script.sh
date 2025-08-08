#!/bin/bash

# Set the path to the Python script.
SCRIPT_PATH="work/script.py"

# Print the script.
cat "$SCRIPT_PATH"

echo "Running the script... in sh"
# Run it using Python.
timeout 60 python3 "$SCRIPT_PATH" "$@"
