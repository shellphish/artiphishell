#!/bin/bash

set -x
set -e

if [ "$1" != 'CI' ]; then
    docker login ghcr.io -u player-c3f09220 -p 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

    pushd ../../../../../local_run/
    ./rebuild_local.sh || true
    popd
    # pushd ../../../../common/base/crs-utils
    # docker build -t aixcc-crs-utils .
    # popd
    pushd ../../
    docker build -t aixcc-libfuzzer .
    popd
fi

if [ ! -d targets-semis-aixcc-sc-challenge-004-nginx-cp ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp
    (
        pushd targets-semis-aixcc-sc-challenge-004-nginx-cp
        make cpsrc-prepare
        make docker-pull
        popd
    )
fi
if [ ! -f targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz ]; then
    tar czf targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz -C targets-semis-aixcc-sc-challenge-004-nginx-cp .
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name libfuzzer_feature_test_nginx_cp
pd inject analyze_target.target_with_sources 1 < targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz
echo works: true | pd inject libfuzzer_build.target_image_id 1
pd --verbose run
