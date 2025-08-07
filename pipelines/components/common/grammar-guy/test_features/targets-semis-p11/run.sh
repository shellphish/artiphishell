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

if [ ! -d targets-semis-p11-kit-57202 ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-p11-kit-57202.git
    (
        pushd targets-semis-p11-kit-57202
        set -x
        make cpsrc-prepare
        popd
    )
fi
if [ ! -f targets-semis-p11-kit-57202.tar.gz ]; then
    tar czf targets-semis-p11-kit-57202.tar.gz -C targets-semis-p11-kit-57202 .
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name grammar_guy_feature_test_p11_kit
pd inject analyze_target.target_with_sources 1 < targets-semis-p11-kit-57202.tar.gz
# ./restore_backup.sh # backup to restore_latest_state
pd --verbose run

