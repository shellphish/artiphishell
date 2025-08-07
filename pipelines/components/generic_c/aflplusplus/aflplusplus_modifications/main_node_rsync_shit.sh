#!/bin/bash

set -u
set -e
set -x

CP_NAME="${CP_NAME}"
HARNESS_NAME="${CP_HARNESS_NAME}"


# [
#     {"ip": "172.10.0.1", "self": true}
# ]

RELPATH="aflpp_sync/${CP_NAME}-${HARNESS_NAME}/"

while true; do    
    export NODE_IP="${NODE_IP:-localhost}"
    if ! curl "${NODE_IP}:7677/nodes" > /tmp/nodes.json; then
        echo '[{"ip": "127.0.0.1", "self": true}]' > /tmp/nodes.json
    fi

    SELF_NODE=$(jq -r '. [] | select(.self == true) | .ip' /tmp/nodes.json)
    OTHER_NODES=$(jq -r '.[] | select(.self == false) | .ip' /tmp/nodes.json)

    mkdir -p "/shared/$RELPATH/main/crashes/" "/shared/$RELPATH/main_crashsync/queue/"

    for f in /shared/"$RELPATH"/*/crashes/; do
        rsync -ra --mkpath "$f" "/shared/$RELPATH/main/crashes/"
        rsync -ra --mkpath "$f" "/shared/$RELPATH/main_crashsync/queue/"
    done

    for other_node in $OTHER_NODES; do
        echo "Syncing with $other_node ..."
        mkdir -p /shared/$RELPATH/${other_node}/{queue,crashes}
        mkdir -p /shared/$RELPATH/${other_node}_crashsync/queue/

        rsync -raz --mkpath "/shared/$RELPATH/main/queue/"    "$other_node::shared/$RELPATH/${SELF_NODE}/queue/" || true
        rsync -raz --mkpath "/shared/$RELPATH/main/crashes/"  "$other_node::shared/$RELPATH/${SELF_NODE}/crashes/" || true
        rsync -raz --mkpath "/shared/$RELPATH/main/crashes/"  "$other_node::shared/$RELPATH/${SELF_NODE}_crashsync/queue/" || true

        rsync -raz --mkpath "$other_node::shared/$RELPATH/main/queue/"      "/shared/$RELPATH/${other_node}/queue/" || true
        rsync -raz --mkpath "$other_node::shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}/crashes/" || true
        rsync -raz --mkpath "$other_node::shared/$RELPATH/main/crashes/"    "/shared/$RELPATH/${other_node}_crashsync/queue" || true
    done

    echo "Sleeping for 2 minutes ..."
    sleep 120
done
