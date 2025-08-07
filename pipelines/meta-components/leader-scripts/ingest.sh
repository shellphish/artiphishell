#!/usr/bin/env bash

set -o pipefail

# THIS SCRIPT IS A WORKER THAT RUNS INSIDE THE CLUSTER - DO NOT CONFUSE WITH shellphish-crs/scripts/ingest.sh

cd "$(dirname "$0")" || { echo "huh?" && exit 1; }
. /root/venv/bin/activate

while ! pd status &>/dev/null; do
    echo "Waiting for pd to be ready"
done

while ! curl http://agent:9595/health &>/dev/null; do
    echo "Waiting for agent to be ready"
done

pending_watchdog() {
    echo "Started pending watchdog"
    while true; do
        if kubectl get pods -l replica=0 -o yaml 2>/dev/null | yq '.items | filter((.status.conditions | filter(.reason == "Unschedulable") | any()) and ((.metadata.creationTimestamp | to_unix) + 60*3 < (now | to_unix))) | any()' --exit-status &>/dev/null; then
            echo "COMMENCE PENDING WATCHDOG MURDER"
            kubectl delete pods -l preemptable=true
            sleep $((60*3))
        fi
        sleep 10
    done
}

pending_watchdog &

docker_watchdog() {
    echo "Started docker watchdog"
    i=0
    while true; do
        i=$((i + 1))
        kubectl get pods -o yaml | yq '.items | filter(.metadata.labels.app == "aixcc") | map(.metadata.labels.task + "___" + .metadata.labels.job + "___" + .metadata.labels.replica)' >/tmp/live_workers-$i.yaml || continue
        for node in $(kubectl get pods -l shellphish-app=docker-api -o yaml | yq '.items | map(.status.hostIP) | .[]'); do
            export DOCKER_HOST=tcp://$node:7523
            docker ps --format json | jq --slurp | python3 dockerparse.py >/tmp/live_containers-$node-$i.json
            yq '(. | keys) - load("/tmp/live_workers-'$i'.yaml")' </tmp/live_containers-$node-$i.json >/tmp/zombie_containers-$node-$i.yaml
            if yq '. | any' --exit-status </tmp/zombie_containers-$node-$i.yaml &>/dev/null; then
                echo "COMMENCING DOCKER MURDER $node $i"
                docker rm -f $(yq 'pick(load("/tmp/zombie_containers-'$node-$i'.yaml")) | map(.) | flatten | .[]' </tmp/live_containers-$node-$i.json)
            fi
        done
        sleep 30
    done
}

docker_watchdog &

echo "Listening for new CPs at $AIXCC_CP_ROOT"

mkdir /root/ingested
while true; do
    (cd "$AIXCC_CP_ROOT" && find . -type d -mindepth 1 -maxdepth 1) | while read -r cp_filename; do
        [[ -z "$cp_filename" || "$cp_filename" = "lost+found" ]] && continue
        if ! [ -e "/root/ingested/$cp_filename.yaml" ]; then
            LAST_ID="$(pd ls pipeline_inputs.target_with_sources | sort -n | tail -n1)"
            ident=$((LAST_ID + 1))
            (cd "$AIXCC_CP_ROOT/$cp_filename" && tar --owner=0 --group=0 -czf "/root/ingested/$cp_filename.tar.gz" .)
            echo "ingesting $cp_filename as $ident..."
            pd inject pipeline_inputs.target_with_sources "$ident" <"/root/ingested/$cp_filename.tar.gz"
            (
                echo "id: '$ident'"
                echo "orig_filename: $cp_filename"
            ) >"/root/ingested/$cp_filename.yaml"
            echo "...ingested"
        fi
    done
    sleep 5
done
