#!/bin/bash

set +x
. tmp/.env


function logs() {
    API_POD=$(kubectl get pod -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}')

    kubectl logs -f $API_POD
}

function watch() {
    while true; do
        logs
        sleep 5
    done
}

if [[ " $@ " =~ " -w " ]]; then
    watch
else
    logs
fi