#!/bin/bash

set -e
set -x

if [ $# -lt 3 ]; then
    echo "Usage: $0 <syscall_trace> <vmlinux> <output_file>"
    exit 1
fi

SYSCALL_TRACE="$1"
VMLINUX="$2"
OUTPUT_FILE="$3"

data=$(systrack --arch x64 "$VMLINUX" | awk '{print $3 " " $4}')
echo "Data: $data"

symbols=()
while read -r syscall; do
    symbol=$(grep "$syscall " <<< "$data" | awk '{print $2}')
    if [ -n "$symbol" ]; then
        symbols+=("$symbol")
    fi
done < "$SYSCALL_TRACE"

if [ -f "$OUTPUT_FILE" ]; then
    rm "$OUTPUT_FILE"
fi

for sym in "${symbols[@]}"; do
    echo "Symbol: $sym"
    line=$(nm -S "$VMLINUX" | grep " $sym$" | awk '{print $1 " " $2}')
    echo "Line: $line"
    addr="0x$(echo "$line" | awk '{print $1}')"
    sz="0x$(echo "$line" | awk '{print $2}')"
    end_addr=$(printf "%#x" $((addr + sz)))
    echo "$addr,$end_addr" >> "$OUTPUT_FILE"
done

echo "[*] Done"