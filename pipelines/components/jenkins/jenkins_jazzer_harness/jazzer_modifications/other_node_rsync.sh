#!/bin/bash

set -u
set -e
set -x

function local_sync() {
    echo
    echo
    echo
    echo "========= Syncing Local Harness Inputs =========="
    echo "Syncing harness inputs"
    

    # Copy an injected seeds from the dump dir to the sync dir
    rsync -ra "${FUZZ_DUMP_DIR}/benign_harness_inputs/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
    rsync -ra "${FUZZ_DUMP_DIR}/crashing_harness_inputs/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true

    # Copy our local seeds to the sync dir
    rsync -ra "${CONTAINER_INPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
    rsync -ra --exclude 'timeout*' --exclude 'slow*' "${CONTAINER_OUTPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true
    
    # Copy the sync dir back to our local seeds
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" \
        "${CONTAINER_INPUTS}/" || true
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" \
        "${CONTAINER_OUTPUTS}/" || true

}

while true; do
  local_sync
  sleep 20
done