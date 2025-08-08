#!/bin/bash

cd $(dirname $0)/..

set +x
. tmp/.env

#set -ex

export TAIL=""

if [[ " $@ " =~ " -f " ]]; then
    export TAIL="--tail 1000"
fi

./scripts/select_agent.sh

AGENT_POD=$(cat /tmp/selected_agent_pod)

function logs() {
    kubectl logs $TAIL -f $AGENT_POD
}

function watch() {
    while true; do
        logs
        sleep 5
    done
}

# Check for -w flag in args
if [[ " $@ " =~ " -w " ]]; then
    watch
else
    logs
fi
