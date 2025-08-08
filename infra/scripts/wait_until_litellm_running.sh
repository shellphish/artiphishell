#!/bin/bash

cd $(dirname $0)/..

set -e
set +x

. tmp/.env

timeout 20 scripts/access_k8.sh 1>/dev/null

AGENT_POD=$(kubectl get pod -l app.kubernetes.io/name=litellm -o jsonpath='{.items[0].metadata.name}')

# Loop until we can successfully execute a command on the agent pod
echo "Waiting for litellm pod to be ready..."
while ! kubectl exec $AGENT_POD -- echo "yay" &> /dev/null; do
  echo "💤 Litellm pod is not ready yet, waiting..."
  sleep 5
done

echo "🌅 Litellm pod has started!"

