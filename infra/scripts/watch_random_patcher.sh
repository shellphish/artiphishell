#!/bin/bash

set +x
. tmp/.env

#set -ex

function go() {
    pod=$(kubectl get pods | grep patcher | awk '{print $1}' | shuf | head -n 1)
    if [ -z "$pod" ]; then
        echo "😔  No patchers found..."
        return
    fi
    kubectl logs -f $pod
}



function watch() {
    while true; do
        go
        sleep 20
    done
}

# Check for -w flag in args
if [[ " $@ " =~ " -w " ]]; then
    watch
else
    go
fi
