#!/bin/bash

set +x
. tmp/.env

#set -ex


function logs() {
    ./scripts/select_agent.sh
    AGENT_POD=$(cat /tmp/selected_agent_pod)
    kubectl exec -it $AGENT_POD -- tail -f /tmp/backup.log /pdt/monitor_by_project.log
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
