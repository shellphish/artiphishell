#!/bin/bash
set -xeuo pipefail

cd $(dirname $0)/..

set +x
. tmp/.env
set -x

# Check if workspace name is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <workspace-name>"
    exit 1
fi

WORKSPACE_NAME=$1

pushd tf

terraform init \
    -reconfigure \
    -backend-config="key=terraform.tfstate.$WORKSPACE_NAME"

terraform workspace new "$WORKSPACE_NAME" || terraform workspace select "$WORKSPACE_NAME"

popd

./scripts/deploy.sh $@

