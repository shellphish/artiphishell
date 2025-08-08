#!/bin/bash 

if [ $# -lt 3 ]; then
    echo "Usage: $0 <full-path-to-executable> <full-path-to-llvm-symbolizer> <out>"
    exit 1
fi

echo -n > $3 # clear output file

function produce_json() {
    echo $1 $2 $3
    "$2" --exe "$1" --output-style=JSON  | grep -vE "(compiler-rt|covrec|include/c++|InstrProfilingValue.c|cxa_noexception.cpp)"  > "$3" # | awk '/__llvm_profile_write_file/{exit} {print}'
}

produce_json $1 $2 $3

echo "[JSON-PRINTER] Function tracing results saved in $3"
echo "[JSON-PRINTER] DEBUG: len of the output file: $(wc -l $3)"
