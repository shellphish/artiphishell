#!/bin/bash

set -ex 

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Running internal tests"

pushd ${SCRIPT_DIR}/test-internal_stuff
    ./test-internal.sh
popd