#!/bin/bash

set -u
set -e
set -x

NAME_REAL="${ARTIPHISHELL_PROJECT_NAME}"
HARNESS_NAME="${ARTIPHISHELL_HARNESS_NAME}"
HARNESS_INFO_ID="${ARTIPHISHELL_HARNESS_INFO_ID}"


# [
#     {"ip": "172.10.0.1", "self": true}
# ]

RELPATH="fuzzer_sync/${NAME_REAL}-${HARNESS_NAME}-${HARNESS_INFO_ID}/"
FOREIGN_FUZZER_DIR=${ARTIPHISHELL_INTER_HARNESS_SYNC_DIR:-"/tmp/foreign_fuzzer"}
mkdir -p "$FOREIGN_FUZZER_DIR"

FUZZER_SYNC_DIR="/shared/fuzzer_sync"
PROJECT_PREFIX="$ARTIPHISHELL_PROJECT_NAME"
mkdir -p "$FUZZER_SYNC_DIR"


copy_inputs() {
    # This generates a ton of logs. Suppressing it
    src_dir="$1"
    if [ ! -d "$src_dir/queue" ]; then
        return
    fi
    start_time=$(date +%s)
    rsync -ra --exclude='**/.state/' "${src_dir}/queue/" "${FOREIGN_FUZZER_DIR}"
    end_time=$(date +%s)
    time_diff=$((end_time - start_time))
    echo "rsync from $src_dir to $FOREIGN_FUZZER_DIR in $time_diff seconds"
}

while true; do
    export NODE_IP="${NODE_IP:-localhost}"
    export AGENT_IP="${PYDATATASK_AGENT_SERVICE_HOST:-localhost}"
    export AGENT_PORT="${PYDATATASK_AGENT_SERVICE_PORT:-8080}"

    crs-get-sync-nodes > /tmp/sync_nodes.json ||
    curl "${PDT_AGENT_URL}/nodes?node_ip=${NODE_IP}" > /tmp/sync_nodes.json ||
    echo '[{"ip": "127.0.0.1", "self": true}]' > /tmp/sync_nodes.json

    echo "Sync nodes found: "
    cat /tmp/sync_nodes.json

    STALE_THRESHOLD=300 # seconds
    evict_fuzzer_instance_if_stale() {
        local instance_path="$1"
        
        if [ ! -d "$instance_path" ] || [ ! -f "$instance_path/fuzzer_stats" ]; then
            return
        fi
        
        last_update=$(stat -c %Y "$instance_path/fuzzer_stats" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "WARNING: Cannot stat $instance_path/fuzzer_stats"
            return
        fi
        
        current_time=$(date +%s)
        time_diff=$((current_time - last_update))
        if [ $time_diff -gt $STALE_THRESHOLD ]; then
            echo "Evicting stale instance at $instance_path (last updated $time_diff seconds ago)"
            rm -rf "$instance_path"
        fi
    }

    evict_fuzzer_instance_if_stale "/shared/$RELPATH/nautilus/instances/main/"

    SELF_NODE=$(jq -r '. [] | select(.self == true) | .ip' /tmp/sync_nodes.json)
    OTHER_NODES=$(jq -r '.[] | select(.self == false) | .ip' /tmp/sync_nodes.json)

    mkdir -p "/shared/$RELPATH/main/crashes/" "/shared/$RELPATH/main_crashsync/queue/"

    for f in /shared/"$RELPATH"/*/crashes/; do
        # rsync -ra --mkpath "$f" "/shared/$RELPATH/main/crashes/"
        rsync -ra --mkpath "$f" "/shared/$RELPATH/main_crashsync/queue/"
    done

    total_outbound_duration=0
    total_inbound_duration=0
    total_backsync_duration=0

    # look up the self_node .name in the sync_nodes.json
    self_node_name=$(jq -r --arg ip "$SELF_NODE" '.[] | select(.ip == $ip) | .name' /tmp/sync_nodes.json)
    echo "Syncing for self node $SELF_NODE ($self_node_name) ..."

    node_count=0

    for other_node in $OTHER_NODES; do

        # look up the corresponding .name in the sync_nodes.json
        other_node_name=$(jq -r --arg ip "$other_node" '.[] | select(.ip == $ip) | .name' /tmp/sync_nodes.json)
        # If the name is not found, use the IP as the name
        if [ -z "$other_node_name" ]; then
            other_node_name="$other_node"
        fi
        echo "Syncing with node $other_node ($other_node_name) ..."

        echo "Syncing with $other_node ..."
        node_count=$((node_count + 1))

        SSH_ARGS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        if [ ! -z "$SSH_KEY" ]; then
            SSH_ARGS="-i $SSH_KEY $SSH_ARGS"
        fi

        mkdir -p /shared/$RELPATH/${other_node}_${other_node_name}/{queue,crashes}
        mkdir -p /shared/$RELPATH/${other_node}_${other_node_name}_crashsync/queue/

        ######################################### OUTBOUND SYNC START #########################################
            # Start timing for outbound sync
            outbound_start=$(date +%s)

            # Outbound syncs (from us to other node)
            # telemetry-cli run --attribute "aflpp.sync_direction=outbound" --attribute "aflpp.sync_target=$other_node" "aflpp" "fuzzing" "rsync" "aflpp.rsync_outbound" \
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/queue/"                          "$other_node:/shared/$RELPATH/${SELF_NODE}_${self_node_name}/queue/" || true
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/nautilus/instances/main/queue/"       "$other_node:/shared/$RELPATH/nautilus/instances/${SELF_NODE}_${self_node_name}/queue/" || true
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/crashes/"                        "$other_node:/shared/$RELPATH/${SELF_NODE}_${self_node_name}/crashes/" || true
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH"/sync-*                               "$other_node:/shared/$RELPATH/" || true
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/crashes/"                        "$other_node:/shared/$RELPATH/${SELF_NODE}_${self_node_name}_crashsync/queue/" || true

            # Calculate outbound sync duration
            outbound_end=$(date +%s)
            outbound_duration=$((outbound_end - outbound_start))
            total_outbound_duration=$((total_outbound_duration + outbound_duration))
            echo "Outbound sync to $other_node took $outbound_duration seconds"
        ######################################### OUTBOUND SYNC END #########################################



        ######################################### INBOUND SYNC START #########################################
            # Start timing for inbound sync
            inbound_start=$(date +%s)

            # Inbound syncs (from other node to us)
            # telemetry-cli run --attribute "aflpp.sync_direction=inbound" --attribute "aflpp.sync_target=$other_node" "aflpp" "fuzzing" "rsync" "aflpp.rsync_inbound" \
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/queue/"      "/shared/$RELPATH/${other_node}_${other_node_name}/queue/" || true
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/nautilus/instances/main/queue/"      "/shared/$RELPATH/nautilus/instances/${other_node}_${other_node_name}/queue/" || true
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}_${other_node_name}/crashes/" || true
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH"/sync-*           "/shared/$RELPATH/" || true
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}_${other_node_name}_crashsync/queue" || true

            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/injected-seeds/"    "/shared/injected-seeds/" || true

            # Calculate inbound sync duration
            inbound_end=$(date +%s)
            inbound_duration=$((inbound_end - inbound_start))
            total_inbound_duration=$((total_inbound_duration + inbound_duration))
            echo "Inbound sync from $other_node took $inbound_duration seconds"
        ######################################### INBOUND SYNC END #########################################



        ######################################### BACKSYNC START #########################################
            # Start timing for back sync
            backsync_start=$(date +%s)

            # Back syncs (from our corpus on other node to us)
            # telemetry-cli run --attribute "aflpp.sync_direction=backsync" --attribute "aflpp.sync_target=$other_node" "aflpp" "fuzzing" "rsync" "aflpp.rsync_backsync" \
            rsync -raz -e "ssh $SSH_ARGS"  --mkpath "$other_node:/shared/$RELPATH/${SELF_NODE}_${self_node_name}/queue/" "/shared/$RELPATH/main_backsync_${other_node}_${other_node_name}/queue/" || true

            # Calculate back sync duration
            backsync_end=$(date +%s)
            backsync_duration=$((backsync_end - backsync_start))
            total_backsync_duration=$((total_backsync_duration + backsync_duration))
            echo "Back sync from $other_node took $backsync_duration seconds"
        ######################################### BACKSYNC END #########################################

        # Log total sync time
        total_duration=$((outbound_duration + inbound_duration))
        echo "Total sync with $other_node took $total_duration seconds"
    done

    # Output aggregate sync times
    if [ $node_count -gt 0 ]; then
        echo "===== AGGREGATE SYNC STATISTICS ====="
        echo "Total outbound sync duration: $total_outbound_duration seconds"
        echo "Total inbound sync duration: $total_inbound_duration seconds"
        echo "Total sync duration: $((total_outbound_duration + total_inbound_duration)) seconds"
        echo "Average outbound sync duration: $((total_outbound_duration / node_count)) seconds"
        echo "Average inbound sync duration: $((total_inbound_duration / node_count)) seconds"
        echo "===================================="
    fi
    # telemetry-cli run \
    #     --attribute "aflpp.sync_from_duration=$total_inbound_duration" \
    #     --attribute "aflpp.sync_to_duration=$total_outbound_duration" \
    #     --attribute "aflpp.sync_nodes=$node_count" \
    #     --attribute "crs.action.target.harness=${HARNESS_NAME}" \
    #     --attribute "aflpp.sync_total_duration=$((total_outbound_duration + total_inbound_duration))" \
    #     "aflpp" "fuzzing" "rsync" "aflpp.rsync_aggregate"

    # Inject crashes if present
    if [ -d "/shared/injected-seeds" ]; then
        mkdir -p "/shared/$RELPATH/crash_injection/queue/"
        rsync -ra /shared/injected-seeds/* "/shared/$RELPATH/crash_injection/queue/" || true
    fi

    echo "=================== Inter harness sync ======================"
    for harness_dir in "${FUZZER_SYNC_DIR}/${PROJECT_PREFIX}-"*; do
        echo "Copying inputs from $harness_dir/main to $FOREIGN_FUZZER_DIR"
        copy_inputs "${harness_dir}/main"
    done

    echo "Breaking out of loop"
    break
done
