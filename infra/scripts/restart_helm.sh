#!/bin/bash

cd $(dirname $0)/..

set +x
. tmp/.env
set -x

./scripts/stop_helm.sh

./scripts/deploy.sh $@