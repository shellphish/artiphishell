#!/bin/bash

set -x
set -e

docker login ghcr.io -u player-c3f09220 -p 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

# pushd ../../../../../local_run/
# ./rebuild_local.sh || true
# popd
pushd ../../../../../components/common/base/
docker build -t aixcc-component-base -f Dockerfile.component-base .
popd
pushd ../../
docker build -t aixcc-codeql .
popd

if [ ! -d targets-semis-aixcc-sc-challenge-004-nginx-cp ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp
    (
        pushd targets-semis-aixcc-sc-challenge-004-nginx-cp
        make cpsrc-prepare
        popd
    )
fi
if [ ! -f targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz ]; then
    tar czf targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz -C targets-semis-aixcc-sc-challenge-004-nginx-cp .
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name codeql_feature_test_nginx_cp
pd inject analyze_target.target_with_sources 1 < targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz
echo works: true | pd inject codeql_image_build.cp_image_ready 1
pd --verbose --debug-trace run
