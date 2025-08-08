#! /bin/bash
set -e

# build harness
afl-clang-fast -fsanitize=address harness.c -o harness

# build mutator and watchtower
pushd ..
./build.sh
popd

# generate inputs
rm -rf ./input && mkdir -p ./input
../target/release/watchtower sync-grammars -i ./testgrammars -o ./input &
sleep 2

# run fuzzer
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_DISABLE_TRIM=1
export AFL_CUSTOM_MUTATOR_LIBRARY=../target/release/librevolver_mutator.so
export AFL_POST_PROCESS_KEEP_ORIGINAL=1
export AFL_DEBUG=1

afl-fuzz -i input -o output -- ./harness @@

# kill watchtower
pkill watchtower