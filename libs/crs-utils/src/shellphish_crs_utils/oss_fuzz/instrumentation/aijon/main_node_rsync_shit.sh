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

while true; do    
    export NODE_IP="${NODE_IP:-localhost}"
    export AGENT_IP="${PYDATATASK_AGENT_SERVICE_HOST:-localhost}"
    export AGENT_PORT="${PYDATATASK_AGENT_SERVICE_PORT:-8080}"
    if ! curl "${PDT_AGENT_URL}/nodes?node_ip=${NODE_IP}" > /tmp/nodes.json; then
        echo '[{"ip": "127.0.0.1", "self": true}]' > /tmp/nodes.json
    fi

    SELF_NODE=$(jq -r '. [] | select(.self == true) | .ip' /tmp/nodes.json)
    OTHER_NODES=$(jq -r '.[] | select(.self == false) | .ip' /tmp/nodes.json)

    mkdir -p "/shared/$RELPATH/main/crashes/" "/shared/$RELPATH/main_crashsync/queue/"

    for f in /shared/"$RELPATH"/*/crashes/; do
        # rsync -ra --mkpath "$f" "/shared/$RELPATH/main/crashes/"
        rsync -ra --mkpath "$f" "/shared/$RELPATH/main_crashsync/queue/"
    done

    for other_node in $OTHER_NODES; do
        echo "Syncing with $other_node ..."

        SSH_ARGS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        if [ ! -z "$SSH_KEY" ]; then
            SSH_ARGS="-i $SSH_KEY $SSH_ARGS"
        fi

        mkdir -p /shared/$RELPATH/${other_node}/{queue,crashes}
        mkdir -p /shared/$RELPATH/${other_node}_crashsync/queue/

        rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/queue/"    "$other_node:/shared/$RELPATH/${SELF_NODE}/queue/" || true
        rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/crashes/"  "$other_node:/shared/$RELPATH/${SELF_NODE}/crashes/" || true
        rsync -raz -e "ssh $SSH_ARGS"  --mkpath "/shared/$RELPATH/main/crashes/"  "$other_node:/shared/$RELPATH/${SELF_NODE}_crashsync/queue/" || true

        rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/queue/"      "/shared/$RELPATH/${other_node}/queue/" || true
        rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}/crashes/" || true
        rsync -raz -e "ssh $SSH_ARGS" --mkpath "$other_node:/shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}_crashsync/queue" || true
    done

    # Inject crashes if present
    if [ -d "/shared/injected-seeds" ]; then
        rsync -ra /shared/injected-seeds/* "/shared/$RELPATH/main/crashes/" || true
    fi

    echo "Sleeping for 2 minutes ..."
    sleep 120
done
