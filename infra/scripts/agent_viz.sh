#!/bin/bash

cd $(dirname $0)/..

set -ex

set +x 
. tmp/.env
set -x

./scripts/select_agent.sh

AGENT_POD=$(cat /tmp/selected_agent_pod)

# Get the public IP of the API service
while [ -z "$(kubectl get service pydatatask-agent-debug -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)" ]; do
  echo "Waiting for pdt-agent LoadBalancer to get public IP..."
  sleep 5
done

AGENT_IP=$(kubectl get service pydatatask-agent-debug -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "pd viz will be accessible at: http://$AGENT_IP:5555"

kubectl exec $AGENT_POD -- /app/infra/agent/agent_viz.sh