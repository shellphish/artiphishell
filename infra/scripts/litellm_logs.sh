#!/bin/bash

set +x
. tmp/.env

#set -ex


function logs() {
    AGENT_POD=$(kubectl get pod -l app.kubernetes.io/name=litellm -o jsonpath='{.items[0].metadata.name}')
    kubectl logs -f $AGENT_POD
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
