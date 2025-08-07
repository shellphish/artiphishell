#!/bin/bash

set -x

CUR_DIR=$(pwd)

cd fuzz_clib/

if [ ! -f ./targets-semis-clib.tar.gz ]; then
    rm -rf ./targets-semis-clib
    git clone https://github.com/shellphish-support-syndicate/targets-semis-clib
    pushd targets-semis-clib
    ./run.sh pull_source
    tar -cvzf ../targets-semis-clib.tar.gz ./
    popd
    rm -rf ./targets-semis-clib
fi

pdl --unlock || rm -rf pipeline.lock

pdl
pd inject libfuzzer_build.target 1 < ./targets-semis-clib.tar.gz

pd --verbose --debug-trace run
