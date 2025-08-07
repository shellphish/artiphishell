#!/bin/bash

set -x
set -e

docker login ghcr.io -u player-c3f09220 -p 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

pushd ../../../../../local_run/
./rebuild_local.sh
popd
pushd ../../../../common/base/
docker build -f Dockerfile.component-base -t aixcc-component-base .
popd
pushd ../../
docker build -t aixcc-aflplusplus .
popd

# if [ ! -d targets-semis-aixcc-sc-mock-cp ]; then
#     git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp
#     (
#         pushd targets-semis-aixcc-sc-mock-cp
#         make cpsrc-prepare
#         make docker-pull
#         popd
#     )
# fi
# if [ ! -f targets-semis-aixcc-sc-mock-cp.tar.gz ]; then
#     tar czf targets-semis-aixcc-sc-mock-cp.tar.gz -C targets-semis-aixcc-sc-mock-cp .
# fi

# sleep 10
if [ ! -d backup ]; then
    unar backup.tar.gz
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name aflplusplus_patch

pd restore ./backup --all

pd rm aflpp_patch_build __all__
pd rm aflpp_patch_build_cmplog __all__
pd rm aflpp_patch_fuzz __all__
# pd inject analyze_target.target_with_sources 1 < targets-semis-aixcc-sc-mock-cp.tar.gz
# echo works: true | pd inject aflpp_build_image.target_id 1
pd --verbose --debug-trace -t aflpp_patch_build -t aflpp_patch_build_cmplog -t aflpp_patch_fuzz run
