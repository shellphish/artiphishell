#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

TARGET_DIR="$PWD"

PIPELINE_FILE=$1
DURATION="${2:-600}"

BACKUP_DIR=../../backups/poiguy_kasan_backup

../common/rebuild_dependency_dockers.sh

cp "../pipelines/$PIPELINE_FILE" ./pipeline.yaml

pdl --unlock || rm -rf pipeline.lock
ipython --pdb $(which pdl) -- --long-running-timeout $((DURATION / 60))

pd restore "$BACKUP_DIR" --all

set +e
timeout -s INT "${DURATION}" pd --verbose --fail-fast --debug-trace run
set -e

pd status -j | python3 check_results.py
