#!/bin/bash

set -x
set -e

docker login ghcr.io -u player-c3f09220 -p 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

# pushd ../../../../../local_run/
# ./rebuild_local.sh
# popd
pushd ../../../../common/base/
docker build -f Dockerfile.component-base -t aixcc-component-base .
popd
pushd ../../
docker build -t aixcc-aflplusplus .
popd

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

# wait for enter
read -p "Press enter to continue"
pdl --unlock || rm -rf pipeline.lock
pdl --name aflplusplus_feature_test_nginx_cp
pd inject analyze_target.target_with_sources 1 < targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz
echo works: true | pd inject aflpp_build_image.target_id 1
pd --verbose run
