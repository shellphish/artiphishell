#!/bin/bash

# if first argument is "clean"
if [ "$1" == "clean" ]; then
    echo "[*] Trying to clean"
    rm -rf build
fi

# get the current directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

mkdir -p $DIR/build
echo "[*] Trying to Run Cmake"
cd $DIR/build
cmake .. \
  -DCMAKE_CXX_COMPILER=/usr/lib/llvm-18/bin/clang++ \
  -DCMAKE_C_COMPILER=/usr/lib/llvm-18/bin/clang
echo "[*] Trying to make"
make -j$(nproc)

# Fail if copy fails
cp FuncCov/FunctionCoverage.so ../ 2>/dev/null