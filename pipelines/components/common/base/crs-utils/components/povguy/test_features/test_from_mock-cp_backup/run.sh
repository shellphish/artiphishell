#!/bin/bash

set -x
set -e

docker login ghcr.io -u player-c3f09220 -p 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

# pushd ../../../../../local_run/
# ./rebuild_local.sh
# popd
pushd ../../../../../
docker build -f Dockerfile.component-base -t aixcc-component-base .
popd

if [ ! -d targets-semis-aixcc-sc-mock-cp ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp
    (
        pushd targets-semis-aixcc-sc-mock-cp
        make cpsrc-prepare
        make docker-pull
        popd
    )
fi
if [ ! -f targets-semis-aixcc-sc-mock-cp.tar.gz ]; then
    tar czf targets-semis-aixcc-sc-mock-cp.tar.gz -C targets-semis-aixcc-sc-mock-cp .
fi

# sleep 10
pdl --unlock || rm -rf pipeline.lock
pdl --name povguy_feature_test_mock_cp
pd restore ./backup --all
pd rm canonical_build __all__
pd rm povguy __all__
pd inject canonical_build.target_with_sources 1 < targets-semis-aixcc-sc-mock-cp.tar.gz
echo works: true | pd inject canonical_build.target_id 1
pd --verbose --debug-trace run
