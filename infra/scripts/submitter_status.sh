#!/bin/bash

set +x
. tmp/.env

#set -ex

./scripts/select_agent.sh

function logs() {
    (
    AGENT_POD=$(cat /tmp/selected_agent_pod)
    kubectl exec -it $AGENT_POD -- pd status submitter | tee /tmp/status
    grep -o "submitter\.vulnerability_submission.*" /tmp/status | grep -o "bead3fe07525542b9cd4daed7e8cdc64.*2ba4ee6981fc7633461d63523ec4577c" | tr -d '(),' | sed 's/.*\(bead3fe07525542b9cd4daed7e8cdc64\)/\1/'

    kubectl exec -it $AGENT_POD -- pd ls submitter.vulnerability_submission | grep -o "[a-f0-9]\{32\}" | tr '\n' ' ' | sed 's/ $//' > /tmp/vulnerability_submission_ids
    kubectl exec -it $AGENT_POD -- pd ls submitter.patch_submission | grep -o "[a-f0-9]\{32\}" | tr '\n' ' ' | sed 's/ $//' > /tmp/patch_submission_ids

    #cat /tmp/vulnerability_submission_ids
    #cat /tmp/patch_submission_ids


    echo "🐛🐛🐛 Vulns 🐛🐛🐛"
    for id in $(cat /tmp/vulnerability_submission_ids); do
        echo "- 🐛 $id"
        kubectl exec -it $AGENT_POD -- pd cat submitter.vulnerability_submission $id
    done
    echo "🩹🩹🩹 Patches 🩹🩹🩹"
    for id in $(cat /tmp/patch_submission_ids); do
        echo "- 🩹 $id"
        kubectl exec -it $AGENT_POD -- pd cat submitter.patch_submission $id
    done
) > /tmp/status_print
    cat /tmp/status_print
}

function watch() {
    while true; do
        logs
        sleep 120
    done
}

# Check for -w flag in args
if [[ " $@ " =~ " -w " ]]; then
    watch
else
    logs
fi
