#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

TARGET_DIR="$PWD"

if [ $# -eq 0 ]; then
    echo "usage: run.sh <backup_path>"
fi

BACKUP_DIR=$1

pushd ../../
docker build -t aixcc-poi-guy .
popd

pdl --unlock || rm -rf pipeline.lock
pdl

pd restore "$BACKUP_DIR" --all

set +e
pd --verbose --fail-fast --debug-trace run
set -e

pd status
