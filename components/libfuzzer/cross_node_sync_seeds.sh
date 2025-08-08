#! /bin/bash

# [
#     {"ip": "172.10.0.1", "self": true}
# ]

set -x


###
# cross-node sync
###

# create key value pairs for harness name and harness id

declare -A HARNESS

while read -r id name; do
  HARNESS["$id"]="$name"
done < <(
  yq e -r '.harness_infos
            | to_entries[]
            | "\(.key) \(.value.cp_harness_name)"' \
        "$TARGET_SPLIT_METADATA"
)


while true; do 

        ############################
        #### Collect sync nodes ####
        ############################
               
        export NODE_IP="${NODE_IP:-localhost}"
        export AGENT_IP="${PYDATATASK_AGENT_SERVICE_HOST:-localhost}"
        export AGENT_PORT="${PYDATATASK_AGENT_SERVICE_PORT:-8080}"

        crs-get-sync-nodes > /tmp/sync_nodes.json ||
        curl "${PDT_AGENT_URL}/nodes?node_ip=${NODE_IP}" > /tmp/sync_nodes.json ||
        echo '[{"ip": "127.0.0.1", "self": true}]' > /tmp/sync_nodes.json

        echo "Sync nodes found: "
        cat /tmp/sync_nodes.json

        SELF_NODE=$(jq -r '. [] | select(.self == true) | .ip' /tmp/sync_nodes.json)
        OTHER_NODES=$(jq -r '.[] | select(.self == false) | .ip' /tmp/sync_nodes.json)

        echo "Nodes: $(cat /tmp/sync_nodes.json)"
        echo "Self node: $SELF_NODE"
        echo "Other nodes: $OTHER_NODES"

        total_outbound_duration=0
        total_inbound_duration=0
        node_count=0

        for other_node in $OTHER_NODES; do
            echo "=========================================="
            echo "Syncing with node: $other_node"
            echo "=========================================="
            node_count=$((node_count + 1))

            SSH_ARGS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
            if [ ! -z "$SSH_KEY" ]; then
                SSH_ARGS="-i $SSH_KEY $SSH_ARGS"
            fi

            # Create directories for each harness on the local and remote nodes
            for harness_id in "${!HARNESS[@]}"; do
                harness_name=${HARNESS[$harness_id]}
                ARTIPHISHELL_HARNESS_NAME=$harness_name
                ARTIPHISHELL_HARNESS_INFO_ID=$harness_id

                echo "Found harness: $ARTIPHISHELL_HARNESS_NAME with id: $ARTIPHISHELL_HARNESS_INFO_ID"

                export LIBFUZZER_INSTANCE_UNIQUE_NAME=${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/
                export ARTIPHISHELL_FUZZER_SYNC_PATH="/shared/fuzzer_sync/$LIBFUZZER_INSTANCE_UNIQUE_NAME"

                # create directories for each harness on local node
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/"
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/"
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/nonsync-discoguy"
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/nonsync-grammar-agent-explore"
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/nonsync-grammarroomba"
                mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/nonsync-grammar-guy-fuzz"
        
                # create directories for each harness on remote node
                echo "Creating directories on $other_node ..."
                ssh $SSH_ARGS $other_node "mkdir -p $ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/ $ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" || true


                ## Some sync stats. may disable this later
                echo "Local node queue before sync: $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/" | wc -l) files"
                echo "Local node crashes before sync: $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" | wc -l) files"
 
            done
            
            # Pattern matching all project harnesses
            FUZZER_SYNC_TARGET_BASEPATH="/shared/fuzzer_sync/${ARTIPHISHELL_PROJECT_NAME}-*"

            ########################
            #### OUTBOUND SYNC #####
            ########################

            # Copy our queue and crashes to the remote node
            echo "Copying seeds to $other_node..."
            # Start timing for outbound sync
            outbound_start=$(date +%s)
            # telemetry-cli run --attribute "libfuzz.sync_direction=outbound" --attribute "libfuzz.sync_target=$other_node" "libfuzz" "fuzzing" "rsync" "libfuzz.rsync_outbound" \

            rsync -raz --relative -e "ssh $SSH_ARGS" "$FUZZER_SYNC_TARGET_BASEPATH/libfuzzer-minimized/queue/" "$other_node:/" || true
            rsync -raz --relative -e "ssh $SSH_ARGS" "$FUZZER_SYNC_TARGET_BASEPATH/libfuzzer-all/crashes/" "$other_node:/" || true
            rsync -raz --relative -e "ssh $SSH_ARGS" "$FUZZER_SYNC_TARGET_BASEPATH/"sync-* "$other_node:/" || true
            
            # Calculate outbound sync duration
            outbound_end=$(date +%s)
            outbound_duration=$((outbound_end - outbound_start))
            total_outbound_duration=$((total_outbound_duration + outbound_duration))
            echo "Outbound sync to $other_node took $outbound_duration seconds"


            ########################
            #### INBOUND SYNC #####
            ########################

            # Start timing for inbound sync
            inbound_start=$(date +%s)
            # Copy remote node's queue and crashes to our local node
            echo "Copying seeds from $other_node..."
            # telemetry-cli run --attribute "libfuzz.sync_direction=inbound" --attribute "libfuzz.sync_target=$other_node" "libfuzz" "fuzzing" "rsync" "libfuzz.rsync_inbound" \
            rsync -raz --relative -e "ssh $SSH_ARGS" "$other_node:$FUZZER_SYNC_TARGET_BASEPATH/libfuzzer-minimized/queue/" "/" || true
            rsync -raz --relative -e "ssh $SSH_ARGS" "$other_node:$FUZZER_SYNC_TARGET_BASEPATH/libfuzzer-all/crashes/" "/" || true
            rsync -raz --relative -e "ssh $SSH_ARGS" "$other_node:$FUZZER_SYNC_TARGET_BASEPATH"/sync-* "/" || true
            
            rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/injected-seeds/"    "/shared/injected-seeds/" || true

            # Calculate inbound sync duration
            inbound_end=$(date +%s)
            inbound_duration=$((inbound_end - inbound_start))
            total_inbound_duration=$((total_inbound_duration + inbound_duration))
            echo "Inbound sync from $other_node took $inbound_duration seconds"

            echo "Sync with $other_node completed."

            echo "=========================================="
            echo "Now lets sync all our disco-guy seeds into a new directory"
            echo "=========================================="

            # This assumes that once you get here we have all the disco-guy seeds in our /shared/harness/sync-discoguy-*/ dir. Lets move all those into a
            # nonsync dir on this node only
            # lets move all the seeds from the sync-discoguy-* dirs to a nonsync dir
            # List all the sync-discoguy-* directories
            for dir in $(find ${FUZZER_SYNC_TARGET_BASEPATH} -maxdepth 1 -type d -name "sync-discoguy-*"); do
                echo "Found disco guy directory: $dir"
                if [ -d "$dir/queue" ]; then
                    queue_count=$(find "$dir/queue" -type f | wc -l)
                    echo "Count of disco-guy seeds in $dir: $queue_count files"
                else
                    echo "[!] No queue directory found in $dir"
                fi
                # extract the dirname of the dir and store into a variable
                dir_name=$(dirname "$dir")
                rsync -raz "$dir/" "$dir_name/nonsync-discoguy/" || true
                echo "$SELF_NODE -> Count of disco-guy seeds in nonsync-discoguy: $(ls "$dir_name/nonsync-discoguy/queue" | wc -l) files"
            done

            # Now lets do the same for "nonsync-grammar-agent-explore" / "queue" 
            # this will also work for delta mode grammar-agent-explore-delta
            echo "=========================================="
            echo "Now lets sync all our grammar-agent-explore seeds into a new directory"
            echo "=========================================="

            for dir in $(find ${FUZZER_SYNC_TARGET_BASEPATH} -maxdepth 1 -type d -name "sync-grammar-agent-explore-*"); do
                echo "Found grammar-agent-explore directory: $dir"
                if [ -d "$dir/queue" ]; then
                    queue_count=$(find "$dir/queue" -type f | wc -l)
                    echo "Count of grammar-agent-explore seeds in $dir: $queue_count files"
                else
                    echo "[!] No queue directory found in $dir"
                fi
                # extract the dirname of the dir and store into a variable
                dir_name=$(dirname "$dir")
                rsync -raz "$dir/" "$dir_name/nonsync-grammar-agent-explore/" || true
                echo "$SELF_NODE -> Count of grammar-agent-explore seeds in nonsync-grammar-agent-explore: $(ls "$dir_name/nonsync-grammar-agent-explore/queue" | wc -l) files"
            done    

            # Now lets do the same for "nonsync-grammarroomba" / "queue" 
            # this will also work for delta mode grammarroomba-delta
            echo "=========================================="
            echo "Now lets sync all our grammarroomba seeds into a new directory"
            echo "=========================================="

            for dir in $(find ${FUZZER_SYNC_TARGET_BASEPATH} -maxdepth 1 -type d -name "sync-grammarroomba-*"); do
                echo "Found grammarroomba directory: $dir"
                if [ -d "$dir/queue" ]; then
                    queue_count=$(find "$dir/queue" -type f | wc -l)
                    echo "Count of grammarroomba seeds in $dir: $queue_count files"
                else
                    echo "[!] No queue directory found in $dir"
                fi
                # extract the dirname of the dir and store into a variable
                dir_name=$(dirname "$dir")
                rsync -raz "$dir/" "$dir_name/nonsync-grammarroomba/" || true
                echo "$SELF_NODE -> Count of grammarroomba seeds in grammarroomba: $(ls "$dir_name/nonsync-grammarroomba/queue" | wc -l) files"
            done  

            
            # Now lets do the same for "nonsync-grammar-guy-fuzz" / "queue" 
            # this will also work for delta mode grammar-guy-fuzz-delta
            echo "=========================================="
            echo "Now lets sync all our grammar-guy-fuzz seeds into a new directory"
            echo "=========================================="

            for dir in $(find ${FUZZER_SYNC_TARGET_BASEPATH} -maxdepth 1 -type d -name "sync-grammar-guy-fuzz-*"); do
                echo "Found grammar-guy-fuzz directory: $dir"
                if [ -d "$dir/queue" ]; then
                    queue_count=$(find "$dir/queue" -type f | wc -l)
                    echo "Count of grammar-guy-fuzz seeds in $dir: $queue_count files"
                else
                    echo "[!] No queue directory found in $dir"
                fi
                # extract the dirname of the dir and store into a variable
                dir_name=$(dirname "$dir")
                rsync -raz "$dir/" "$dir_name/nonsync-grammar-guy-fuzz/" || true
                echo "$SELF_NODE -> Count of grammar-guy-fuzz seeds in nonsync-grammar-guy-fuzz: $(ls "$dir_name/nonsync-grammar-guy-fuzz/queue" | wc -l) files"
            done  
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
        #     --attribute "libfuzz.sync_from_duration=$total_inbound_duration" \
        #     --attribute "libfuzz.sync_to_duration=$total_outbound_duration" \
        #     --attribute "libfuzz.sync_nodes=$node_count" \
        #     --attribute "crs.action.target.harness=${ARTIPHISHELL_HARNESS_NAME}" \
        #     --attribute "libfuzz.sync_total_duration=$((total_outbound_duration + total_inbound_duration))" \
        #     "libfuzz" "fuzzing" "rsync" "libfuzz.rsync_aggregate"


        ## Some stats after syncing. may disable this later

        echo "Sleeping for 2 minutes ..."
        sleep 120
   
done