#!/bin/bash

set -x
set -e

BACKUP=$(realpath "$1")
if [ ! -d "${BACKUP}" ]; then
    echo "BACKUP $1 not found"
    exit 1
fi
docker login ghcr.io -u player-c3f09220 -p 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

# pushd ../../../../../local_run/
# ./rebuild_local.sh
# popd
pushd ../../../../../
docker build -f Dockerfile.component-base -t aixcc-component-base .
popd


# sleep 10
pdl --unlock || rm -rf pipeline.lock
pdl --name povguy_feature_test_mock_cp
pd restore "$BACKUP" --all
pd rm povguy __all__
pd rm asan2report __all__
pd --verbose --debug-trace run
