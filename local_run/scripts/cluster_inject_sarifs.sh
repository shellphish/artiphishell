#!/bin/bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
CRS_ROOT="$(dirname $SCRIPT_PARENT_DIR)/"

if [ -z "$1" ]; then
    echo "Usage: $0 <project_name>"
    exit 1
fi

PROJECT_NAME="$1"

mkdir -p $SCRIPT_DIR/.shellphish

META_REPO="${META_REPO:=https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-meta}"

META_REPO_PATH="$SCRIPT_DIR/.shellphish/artiphishell-ossfuzz-meta"
if [ ! -d "$META_REPO_PATH" ]; then
    git clone $META_REPO $META_REPO_PATH
fi

pushd $META_REPO_PATH

git fetch
git checkout origin/main

popd

SARIF_DIR="$META_REPO_PATH/$PROJECT_NAME/sarifs"
if [ ! -d "$SARIF_DIR" ]; then
    echo "❌ No sarifs found for project $PROJECT_NAME"
    exit 0
fi

export CRS_API_KEY_ID=${ARTIPHISHELL_API_USERNAME:-shellphish}
export CRS_API_TOKEN=${ARTIPHISHELL_API_PASSWORD:-!!!shellphish!!!}
if [ -f $CRS_ROOT/.task_id ]; then
    export CRS_TASK_ID=$(cat $CRS_ROOT/.task_id)
else
    export CRS_TASK_ID="CAFE0000-0000-0000-0000-000000000002"
fi

if [ -f "$CRS_ROOT/infra/tmp/.env" ]; then
    . $CRS_ROOT/infra/tmp/.env
fi
if [ -f "$CRS_ROOT/infra/tmp/.k8-env" ]; then
    . $CRS_ROOT/infra/tmp/.k8-env
fi

if [ -z "$CLUSTER_IP" ]; then
    CLUSTER_IP=$(timeout 20 $CRS_ROOT/infra/scripts/get_api_ip.sh)

    if [ -z "$CLUSTER_IP" ]; then
        echo "Error: Failed to get cluster IP, make sure the cluster is deployed and you are connected to it"
        exit 1
    fi
fi

CLUSTER_PORT=${CLUSTER_PORT:-80}
$SCRIPT_DIR/generate_challenge_sarif.sh -c "${CLUSTER_IP}:${CLUSTER_PORT}" -s $SARIF_DIR -t $CRS_TASK_ID -x
