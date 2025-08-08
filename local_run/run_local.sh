#!/usr/bin/env bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
export SHOULD_INJECT=${SHOULD_INJECT:-false}

if [ -z "$1" ]; then
    echo "Usage: $0 <target_url> <project_name> [--use-competition-server] [base_commit] [reference_commit]"
    echo "Example: $0 https://github.com/aixcc-finals/example-libpng libpng"
    echo "         $0 https://github.com/aixcc-finals/example-libpng libpng --use-competition-server <base_commit>"
    echo "         $0 https://github.com/aixcc-finals/example-libpng libpng --use-competition-server <base_commit> <reference_commit>"
    exit 1
fi

export TARGET_URL="${1%.git}"
export PROJECT_NAME="$2"
if [ "$3" = "--use-competition-server" ]; then
    export USE_COMPETITION_SERVICE=true
else
    export USE_COMPETITION_SERVICE=false
fi
export BASE_COMMIT="$4"
export REFERENCE_COMMIT="$5"

export USE_COMPETITION_SERVICE=${USE_COMPETITION_SERVICE:-false}
export DISABLE_VDS_TIMEOUT="${DISABLE_VDS_TIMEOUT:=1}"
export DISABLE_GP_TIMEOUT="${DISABLE_GP_TIMEOUT:=1}"
export ARTIPHISHELL_API_USERNAME="shellphish"
export ARTIPHISHELL_API_PASSWORD='!!!shellphish!!!'

# Build the command with conditional reference commit

if [ -z "${USE_COMPETITION_SERVICE:-}" ] || [ "${USE_COMPETITION_SERVICE:-}" = false ]; then
    source $SCRIPT_DIR/run_generate_challenge.sh 

    setup_challenge $TARGET_URL $PROJECT_NAME $USE_COMPETITION_SERVICE $BASE_COMMIT $REFERENCE_COMMIT
fi


# Stops any running docker containers
#sudo systemctl restart docker

function pull_if_not_present() {
    if ! docker inspect $1 > /dev/null 2>&1; then
        docker pull $1
    fi
}

pull_if_not_present gcr.io/oss-fuzz-base/base-runner:latest
pull_if_not_present gcr.io/oss-fuzz-base/base-image:latest
pull_if_not_present gcr.io/oss-fuzz-base/base-clang:latest
pull_if_not_present gcr.io/oss-fuzz-base/base-builder:latest
pull_if_not_present gcr.io/oss-fuzz-base/base-builder-jvm:latest



docker rm -f $(docker ps | grep aixcc- | awk '{print $1}') || true
sudo rm -rf /tmp/pydatatask-* || true
sudo rm -rf /crs_scratch || true

export PATCH_TESTING=${PATCH_TESTING:-}

if [ ! -z "${PATCH_TESTING}" ]; then
    export SHOULD_INJECT="true"
fi



echo "Inject Crash: $SHOULD_INJECT"
export SHOULD_PD_INJECT=true
# ARVO testing setup 
if [ ! -z "${ARVO_TEST:-}" ]; then
    export RUN_FOREVER="false"
else
    export RUN_FOREVER="true"
fi

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


