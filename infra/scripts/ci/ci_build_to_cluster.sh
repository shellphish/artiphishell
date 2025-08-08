#!/bin/bash

set -ex

INFRA_DIR=$(realpath $(dirname $0)/../)
ROOT_DIR=$(realpath $INFRA_DIR/../)

if [ -z "$WORKER_TOKEN" ]; then
    echo "❌ WORKER_TOKEN is not set, this is required to --ci-build. If you want to build locally, use --build instead."
    exit 1
fi

if [ -z "$EXTERNAL_REGISTRY" ]; then
    echo "❌ EXTERNAL_REGISTRY is not set"
    exit 1
fi

if [ -z "$EXTERNAL_REGISTRY_USERNAME" ]; then
    echo "❌ EXTERNAL_REGISTRY_USERNAME is not set"
    exit 1
fi

if [ -z "$EXTERNAL_REGISTRY_PASSWORD" ]; then
    echo "❌ EXTERNAL_REGISTRY_PASSWORD is not set"
    exit 1
fi

if [ -z "$GITHUB_REF" ]; then
    echo "❌ GITHUB_REF is not set"
    exit 1
fi

ENCODED_PASSWORD=$(echo -n "$EXTERNAL_REGISTRY_PASSWORD" | base64 -w0)

URL=$(curl "https://shellphish-support-syndicate-workers.cf-a92.workers.dev/api/v1/crs/build?token=$WORKER_TOKEN&registry=$EXTERNAL_REGISTRY&username=$EXTERNAL_REGISTRY_USERNAME&password=$ENCODED_PASSWORD&ref=$GITHUB_REF")

echo "🏗️  Build Job: $URL"

RUN_ID=$(basename $URL)

if [ -n "$1" ]; then
    echo $RUN_ID > $1
fi


exit 0

