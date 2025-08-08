#!/bin/bash

set -eux
INPUT_FILE=$(realpath "$1")
OUTPUT_FILE=$(realpath "$2")
if [ -z "$INPUT_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <input_file> <output_file>"
    exit 1
fi

cd "$(dirname "$(readlink -f "$0")")/dedup/exhibition2"
source ./venv/bin/activate
echo $(which python)
python \
    ./generate_crash_state.py \
    --input-file "$INPUT_FILE" \
    --output-file "$OUTPUT_FILE"
