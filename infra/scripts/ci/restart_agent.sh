#!/bin/bash

set +x
. tmp/.env

#set -ex

./scripts/select_agent.sh

AGENT_POD=$(cat /tmp/selected_agent_pod)

kubectl exec $AGENT_POD -- pkill --signal KILL -f 'pydatatask.cli.main'
