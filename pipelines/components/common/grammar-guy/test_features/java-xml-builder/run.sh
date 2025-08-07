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

if [ ! -d targets-semis-java-xmlbuilder ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-java-xmlbuilder.git
    (
        pushd targets-semis-java-xmlbuilder
        set -x
        make cpsrc-prepare
        popd
    )
fi
if [ ! -f targets-semis-java-xmlbuilder.tar.gz ]; then
    tar czf targets-semis-java-xmlbuilder.tar.gz -C targets-semis-java-xmlbuilder .
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name grammar_guy_feature_test_java_xmlbuilder
pd inject analyze_target.target_with_sources 1 < targets-semis-java-xmlbuilder.tar.gz
# ./restore_backup.sh # backup to restore_latest_state
pd --verbose run

