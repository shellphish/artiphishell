#!/bin/bash

cd $(dirname $0)/..

set -e
set +x

. tmp/.env

timeout 20 scripts/access_k8.sh 1>/dev/null

./scripts/select_agent.sh
AGENT_POD=$(cat /tmp/selected_agent_pod)

# Loop until we can successfully execute a command on the agent pod
echo "Waiting for agent pod to be ready..."
while ! kubectl exec $AGENT_POD -- echo "Agent is running" &> /dev/null; do
  echo "💤 Agent pod is not ready yet, waiting..."
  sleep 5
done

echo "🌅 Agent pod has started!"

