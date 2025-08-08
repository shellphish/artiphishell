#!/bin/bash

set -x
set -e
set -u
set -o pipefail

RUN_MODE=${1:-}
CANONICAL_BUILD_ARTIFACTS=${2:-}
CRS_TASKS_ANALYSIS_SOURCE=${3:-}
OUTPUT_DIR=${4:-}

if [[ -z "$RUN_MODE" || -z "$CANONICAL_BUILD_ARTIFACTS" || -z "$CRS_TASKS_ANALYSIS_SOURCE" || -z "$OUTPUT_DIR" ]]; then
    echo "Usage: $0 <RUN_MODE> <CANONICAL_BUILD_ARTIFACTS> <CRS_TASKS_ANALYSIS_SOURCE> <OUTPUT_DIR>"
    echo "All arguments are required."
    exit 1
fi

python run-java-bottom-up.py \
    --mode "$RUN_MODE" \
    --canonical-build-artifact "$CANONICAL_BUILD_ARTIFACTS" \
    --project-source "$CRS_TASKS_ANALYSIS_SOURCE" \
    --output-dir "$OUTPUT_DIR"
