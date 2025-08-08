#!/bin/bash

set -e

INFRA_DIR=$(realpath $(dirname $0)/../)
ROOT_DIR=$(realpath $INFRA_DIR/../)

if [ -z "$WORKER_TOKEN" ]; then
    echo "❌ WORKER_TOKEN is not set, this is required to --ci-build. If you want to build locally, use --build instead."
    exit 1
fi

if [ -z "$1" ]; then
    echo "$0 <run_id>"
    exit 1
fi

RUN_ID=$1
URL="https://github.com/shellphish-support-syndicate/artiphishell/actions/runs/$RUN_ID"

echo "☁️  Build Progress: $URL"

# Wait for the build to finish
while true; do
RES=$(curl -s "https://shellphish-support-syndicate-workers.cf-a92.workers.dev/api/v1/crs/build/status?token=$WORKER_TOKEN&run_id=$RUN_ID")
echo Job Status: $RES...

if [ "$RES" == "succeeded" ]; then
    echo "✅ Build succeeded"
    exit 0
fi

if [ "$RES" == "failed" ]; then
    echo "❌ Build failed. Please see: $URL"
    exit 1
fi

echo "🔄 Waiting for build to finish..."
sleep 10

done
