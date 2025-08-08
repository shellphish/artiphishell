#!/usr/bin/env bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)

if [ -z "$1" ]; then
    echo "Usage: $0 <project_name|project_url>"
    exit 1
fi


ARG="${1%.git}"

# if the PROJECT_URL is a http, https, or git URL, then we can extract the project name from the URL
if [[ "$ARG" =~ ^https?://.* || "$ARG" =~ ^git://.* || "$ARG" =~ ^git@.* ]]; then
    OSS_FUZZ_PROJECT_URL=$ARG
    OSS_FUZZ_PROJECT_NAME=$(basename $ARG)
else
    OSS_FUZZ_PROJECT_NAME=$ARG
fi

export DISABLE_VDS_TIMEOUT="${DISABLE_VDS_TIMEOUT:=1}"
export DISABLE_GP_TIMEOUT="${DISABLE_GP_TIMEOUT:=1}"

mkdir -p $SCRIPT_DIR/targets

TARGET_NAME=oss-fuzz-$OSS_FUZZ_PROJECT_NAME
TARGET_DIR=$(realpath "$SCRIPT_DIR/targets/$TARGET_NAME")

# if the project url is set, then we need to clone the project
if [ ! -z "$OSS_FUZZ_PROJECT_URL" ]; then
    $SCRIPT_DIR/add_git_oss_fuzz_target.sh $OSS_FUZZ_PROJECT_URL
else
    # otherwise, we assume that it is a pre-defined oss-fuzz target
    $SCRIPT_DIR/add_oss_fuzz_target.sh $OSS_FUZZ_PROJECT_NAME
fi

pushd $TARGET_DIR
# Use yq to parse the project.yaml file and get the following values

TARGET_NAME="$OSS_FUZZ_PROJECT_NAME"
TARGET_LANGUAGE="$(yq -r '.language' project.yaml)"
DOCKER_IMAGE="$(yq -r '.shellphish_docker_image' project.yaml)"

TARGET_API_NAME=$(basename $DOCKER_IMAGE | cut -d: -f1)
popd

export TARGET_REPOS="$DOCKER_IMAGE"
export TARGET_MAKE="$TARGET_API_NAME"
export TARGET_SOURCE_REPO="$TARGET_DIR"

export PATH="$SCRIPT_PARENT_DIR/.github/bin/:$PATH"

# Stops any running docker containers
sudo systemctl restart docker

docker rm -f $(docker ps | grep aixcc- | awk '{print $1}') || true
sudo rm -rf /tmp/pydatatask-* || true
sudo rm -rf /crs_scratch || true

$SCRIPT_DIR/watch_capi.py $TARGET_DIR &

if [ ! -z "$ROUND_TIME_SECONDS" ]; then
    timeout $ROUND_TIME_SECONDS $SCRIPT_DIR/run_raw.sh $TARGET_DIR
else
    $SCRIPT_DIR/run_raw.sh $TARGET_DIR
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


