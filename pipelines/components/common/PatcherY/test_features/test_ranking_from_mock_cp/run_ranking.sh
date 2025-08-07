#!/bin/bash

set -x
set -e

# docker login ghcr.io -u player-c3f09220 -p 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

# pushd ../../../../../local_run/
# ./rebuild_local.sh
#
CUR_DIR=$(dirname $(realpath $0))
pushd $CUR_DIR
pushd ../../
if [ -z "$GITHUB_WORKSPACE" ]; then
    docker build -f Dockerfile -t aixcc-patchery .
else
    docker build -f Dockerfile -t aixcc-patchery . --build-arg=IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/
fi
popd

docker login ghcr.io -u player-c3f09220 -p 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


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
    unar backup_3.tar.gz
fi

pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name patchery_feature_test_mock_cp

pd restore ./backup --all
pd rm patchery __all__
pd --verbose --debug-trace -t patchery run

# yq -r .repos.patchery_autologs_patchery.args.basedir ./pipeline.lock
popd
