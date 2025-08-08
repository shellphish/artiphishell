#!/bin/bash

set -x

function retry_until_success() {
local CMD="$@"
local RETRIES=0
local CMD_NAME=$(echo "$CMD" | cut -d' ' -f1-3)

while [ $RETRIES -lt $MAX_RETRIES ]; do
    if [ ! -z "$OUTPUT_FILE" ]; then
    $CMD > $OUTPUT_FILE && return 0
    cat $OUTPUT_FILE
    else
    $CMD && return 0
    fi
    RETRIES=$((RETRIES+1))
    echo "Retrying failed command $CMD_NAME ($RETRIES/$MAX_RETRIES) in $INTERVAL seconds..."
    sleep $INTERVAL
done
return 1
}
export MAX_RETRIES=10
export INTERVAL=10

export OUTPUT_FILE=/tmp/analysisgraph_pod
retry_until_success kubectl get pods -l app.kubernetes.io/name=analysisgraph-$CRS_TASK_NUM -o jsonpath='{.items[0].metadata.name}'
export ANALYSISGRAPH_POD="$(cat /tmp/analysisgraph_pod)"
export OUTPUT_FILE=""

retry_until_success kubectl exec -it $ANALYSISGRAPH_POD -- pkill -f neo4j

export OUTPUT_FILE=/tmp/codeql_pod
retry_until_success kubectl get pods -l app.kubernetes.io/name=codeql-$CRS_TASK_NUM -o jsonpath='{.items[0].metadata.name}'
export CODEQL_POD="$(cat /tmp/codeql_pod)"
export OUTPUT_FILE=""

retry_until_success kubectl exec -it $CODEQL_POD -- pkill -f codeql

export OUTPUT_FILE=/tmp/functionresolver_pod
retry_until_success kubectl get pods -l app.kubernetes.io/name=functionresolver-$CRS_TASK_NUM -o jsonpath='{.items[0].metadata.name}'
export FUNCTIONRESOLVER_POD="$(cat /tmp/functionresolver_pod)"
export OUTPUT_FILE=""

retry_until_success kubectl exec -it $FUNCTIONRESOLVER_POD -- pkill -f functionresolver

