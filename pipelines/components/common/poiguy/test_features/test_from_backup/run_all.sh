#!/bin/bash
# set -e

function run() {
    echo "Running $1 test..."
    set +e
    OUTPUT=$(./scripts/run_single $1 ./backup_$2 2>&1)
    exit_code=$?
    set -e
    if [ $exit_code -ne 0 ]; then
        echo "Test failed with exit code $exit_code"
        echo "$OUTPUT"
        exit 1
    fi
    rm /tmp/poiguy_test_${1}_${2}.log
}

set -ex
run syzkaller poiguy_syzkaller_bakup
#run jazzer jenkins
#run asan mock_cp