#!/bin/bash

cd $(dirname $0)/..

set -ex

set +x
. tmp/.env
set -x

./scripts/select_agent.sh

AGENT_POD=$(cat /tmp/selected_agent_pod)

kubectl exec -it $AGENT_POD -- /bin/bash