#!/usr/bin/env bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)

if [ -z "$1" ]; then
    echo "Usage: $0 <target-git-url> [<target-git-url> ...]"
    exit 1
fi

export DISABLE_VDS_TIMEOUT="${DISABLE_VDS_TIMEOUT:=1}"
export DISABLE_GP_TIMEOUT="${DISABLE_GP_TIMEOUT:=1}"
export FORCE_GIT_SSH="${FORCE_GIT_SSH:=true}"
if [ "$FORCE_GIT_SSH" = "true" ]; then
    echo "$TARGET_GIT_URL" > /tmp/target_git_url
    sed -i 's|https://github.com/|git@github.com:|' /tmp/target_git_url
    TARGET_GIT_URL=$(cat /tmp/target_git_url)
    echo "Updated $1 -> $TARGET_GIT_URL"
fi

TARGET_NAME=$(basename $TARGET_GIT_URL)
TARGET_DIR=$SCRIPT_DIR/targets/$TARGET_NAME



$SCRIPT_DIR/add_git_target.sh $TARGET_GIT_URL

pushd $TARGET_DIR


# Use yq to parse the project.yaml file and get the following values

cat project.yaml

TARGET_NAME="$(yq -r '.cp_name' project.yaml)"
TARGET_LANGUAGE="$(yq -r '.language' project.yaml)"
DOCKER_IMAGE="$(yq -r '.shellphish.docker_image' project.yaml)"
if [ -z "$DOCKER_IMAGE" ] || [ "$DOCKER_IMAGE" = "null" ]; then
    DOCKER_IMAGE="$(yq -r '.docker_image' project.yaml)"
fi

if [ "$DOCKER_IMAGE" = "null" ]; then
    echo "Docker image is null, missing from project.yaml?"
    cat project.yaml
    exit 1
fi


TARGET_API_NAME=$(basename $DOCKER_IMAGE | cut -d: -f1)
popd

export TARGET_REPOS="$DOCKER_IMAGE"
export TARGET_MAKE="$TARGET_API_NAME"
# Proxy for target_dir
export TARGET_SOURCE_REPO="$TARGET_DIR"

export PATH="$SCRIPT_PARENT_DIR/.github/bin/:$PATH"

# Stops any running docker containers
sudo systemctl restart docker

docker rm -f $(docker ps | grep aixcc- | awk '{print $1}') || true
sudo rm -rf /tmp/pydatatask-* || true
sudo rm -rf /crs_scratch || true

$SCRIPT_DIR/watch_capi.py $TASK_PATH &

if [ ! -z "$ROUND_TIME_SECONDS" ]; then
    timeout $ROUND_TIME_SECONDS $SCRIPT_DIR/run_raw.sh $TASK_PATH
else
    $SCRIPT_DIR/run_raw.sh $TASK_PATH
fi

set +e

if [ -f /tmp/pdt-run-id ]; then
    kill -9 $(cat /tmp/pdt-run-id)
fi

sudo kill -s INT $(ps aux | grep python | grep pydatatask  | grep agent-http | awk '{print $2}')
sudo kill -s INT $(ps aux | grep python | grep pydatatask.cli.main  | awk '{print $2}')
sudo kill -9 $(ps aux | grep ingest.sh | grep bash | awk '{print $2}')
sudo kill -9 $(ps aux | grep ci_fix_docker_created | grep bash | awk '{print $2}')
sudo kill -9 $(ps aux | grep watch_capi.py | grep python | awk '{print $2}')

docker pause $(docker ps -aq)
sudo systemctl restart docker


