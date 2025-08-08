#! /bin/bash

set -e
set -x

export HARNESS_INFO="${HARNESS_INFO}"
export AGGREGATED_HARNESS_INFO="${AGGREGATED_HARNESS_INFO}"
export HARNESS_METADATA="${HARNESS_METADATA}"
pushd "$(dirname "$0")" || exit
    python3 prepare_quickseed.py \
        --harnesses-dir "${HARNESS_INFO}" \
        --aggregated-harness "${AGGREGATED_HARNESS_INFO}"  \
        --harness-metadata "${HARNESS_METADATA}" 
popd