#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring
set -u # fail and exit if any variable is used before being set

CP_NAME="$1"
SYNCDIR="$2"
SEEDS_DIR="$3"
CRASHES_DIR="$4"

set +x
function update_files() {
    local in_dir=$1
    local out_dir=$2
    local files_modified_last_10min=$(find $in_dir -type f -mmin -10)
    for file in $files_modified_last_10min; do
        file_sha256=$(sha256sum $file | cut -d ' ' -f 1)
        if [ ! -f "$out_dir/$file_sha256" ]; then
            echo "Copying new $file to $out_dir/$file_sha256"
            cp $file $out_dir/$file_sha256 || true
        fi
    done
}

function local_sync() {
    echo
    echo
    echo
    echo "========= Syncing Local Harness Inputs =========="
    rsync -ra "${CONTAINER_INPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
    rsync -ra --exclude 'timeout*' --exclude 'slow*' "${CONTAINER_OUTPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true
    
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" \
        "${CONTAINER_INPUTS}/" || true
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" \
        "${CONTAINER_OUTPUTS}/" || true
}

while true; do
    local_sync

    echo
    echo
    echo
    echo "========= Syncing with other nodes ========"

    set -x

    export NODE_IP="${NODE_IP:-localhost}"
    if ! curl "${NODE_IP}:7677/nodes" > /tmp/nodes.json; then
        echo '[{"ip": "127.0.0.1", "self": true}]' > /tmp/nodes.json
    fi

    SELF_NODE=$(jq -r '. [] | select(.self == true) | .ip' /tmp/nodes.json)
    OTHER_NODES=$(jq -r '.[] | select(.self == false) | .ip' /tmp/nodes.json)

    for other_node in $OTHER_NODES; do
        echo "Syncing with $other_node ..."
        rsync -raz --mkpath "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" \
            "$other_node::shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
        rsync -raz --mkpath "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" \
            "$other_node::shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true

        # Reverse sync back to our node
        rsync -raz --mkpath "$other_node::shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" \
            "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
        rsync -raz --mkpath "$other_node::shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" \
            "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true
    done

    for i in $(seq 0 6); do
        local_sync

        set +x

        echo
        echo
        echo
        echo "========= Exporting Results To Pydatatask =========="
        # rsync all files that match 'id:*'
        echo "Syncing files for $SYNCDIR to seeds_dir=$SEEDS_DIR and crashes_dir=$CRASHES_DIR"

        update_files $SYNCDIR/benign_harness_inputs $SEEDS_DIR || true
        update_files $SYNCDIR/crashing_harness_inputs $CRASHES_DIR || true

        set -x
        sleep 20
    done
done