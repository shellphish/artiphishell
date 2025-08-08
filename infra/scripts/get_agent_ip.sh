#!/bin/bash

cd $(dirname $0)/..

set -e

set +x
. tmp/.env

timeout 20 scripts/access_k8.sh 1>/dev/null

# Get the public IP of the API service
while [ -z "$(kubectl get service pydatatask-agent-debug-1 -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)" ]; do
  sleep 5
done

AGENT_IP=$(kubectl get service pydatatask-agent-debug-1 -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $AGENT_IP
