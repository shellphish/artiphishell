#!/bin/bash

set -x
set -e

source ../../../local_run/start_services.sh

# Check if there is an argument
if [ $# -eq 0 ]; then
    echo "No backup folder detected..."
    exit 1
fi

BACKUP_FOLDER=$1

# IF the BACKUP_FOLDER is not a directory, exit
if [ ! -d "$BACKUP_FOLDER" ]; then
    echo "No backup folder detected..."
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
LOCAL_TEST=0

LOCAL_TEST=1

# If LOCAL_TEST is set, we are running locally
if [ $LOCAL_TEST -eq 1 ]; then
    pushd ../
        docker build -t aixcc-coverageguy . --no-cache
    popd 
fi

pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name coverageguy-test

# Check if the BACKUP env var is detected
if [ -d "$BACKUP_FOLDER" ]; then
    echo "Restoring from backup"
    pd restore $BACKUP_FOLDER --all
    pd rm coverage_trace __all__ &> /dev/null || true
else
    echo "No backup folder detected..."
    exit 1
fi

pd status

pd --fail-fast --debug-trace --verbose --global-script-env "ARTIPHISHELL_FAIL_EARLY=1" --global-script-env "ANALYSIS_GRAPH_BOLT_URL=$ANALYSIS_GRAPH_BOLT_URL" run 