#!/bin/bash

# Does not need a pipeline.yaml - only runs the grammar guy internal tests
# docker build my grammar-guy whatever
# docker run with -v mount of the files i need and tests folder (.)
set -e
set -x

exit 0
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Running internal tests"

pushd $SCRIPT_DIR
PYTHONUNBUFFERED=TRUE python3 test_internal_stuff.py

# check if exit code == 0 
exit_status=$?
if [ "${exit_status}" -ne 0 ];
then
    exit 1
fi
popd

echo "Exitting" 