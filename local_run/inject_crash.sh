#!/usr/bin/env bash
PROJECT_NAME=$1
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SEEDS_DIR=${SCRIPT_DIR}/injectables/${PROJECT_NAME}/
if [ ! -d "$SEEDS_DIR" ]; then
    echo "Seeds directory $SEEDS_DIR does not exist."
    exit 1
fi

if ! pushd "$SEEDS_DIR" > /dev/null 2>&1; then
    echo "Error: Could not change directory to $SEEDS_DIR"
    exit 1
fi
chmod +x ./inject.sh
if [ ! -x "./inject.sh" ]; then
    echo "Error: inject.sh is not executable or does not exist in $SEEDS_DIR"
    popd > /dev/null
    exit 1
fi

if ! ./inject.sh; then
    echo "Error: inject.sh failed to execute"
    popd > /dev/null
    exit 1
fi

popd > /dev/null