#!/bin/bash
set -ex

SERVER_DIR=$(realpath $(dirname $0))
export EXTERNAL_REGISTRY=${EXTERNAL_REGISTRY:-"ghcr.io/shellphish-support-syndicate"}

export ARTIPHISHELL_API_USERNAME=${ARTIPHISHELL_API_USERNAME:-"shellphish"}
export ARTIPHISHELL_API_PASSWORD=${ARTIPHISHELL_API_PASSWORD:-"!!!shellphish!!!"}
export ARTIPHISHELL_API_URL=${ARTIPHISHELL_API_URL:-"http://localhost:8000"}

if [ ! -z "${ACR_SERVER:-}" ]; then
    echo $ACR_PASSWORD | docker login $ACR_SERVER -u $ACR_USERNAME --password-stdin
    export EXTERNAL_REGISTRY=$ACR_SERVER
fi

pushd $SERVER_DIR
    ./setup.sh
    docker compose build
popd

if [[ -n "$1" ]] && [[ "$1" == "up" ]]; then
    docker compose "$@"
fi

