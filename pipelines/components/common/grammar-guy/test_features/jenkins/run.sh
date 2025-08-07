#!/bin/bash

set -x
set -e

docker login ghcr.io -u player-c3f09220 -p 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

pushd ../../../../../local_run/
./rebuild_local.sh
popd
pushd ../../../../../components/common/base/
docker build -t aixcc-component-base -f Dockerfile.component-base .
popd
pushd ../../
docker build -t aixcc-grammar-guy .
popd

pdl --unlock || rm -rf pipeline.lock
pdl --name grammar_guy_jenkins_test
./restore_backup.sh # backup to restore_latest_state
pd --verbose -t grammar_guy_fuzz run

