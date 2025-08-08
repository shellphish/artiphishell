#!/bin/bash

set -ex 

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Running pipeline tests - I am sick of this sht - just ignore me for now. I am not ready yet."

pushd ${SCRIPT_DIR}/test-pipeline_stuff
    ./test-pipeline.sh
popd