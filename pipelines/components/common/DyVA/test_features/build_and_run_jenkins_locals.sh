#!/usr/bin/bash
set -x

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
TARGET="targets-semis-aixcc-sc-challenge-002-jenkins-cp"

pushd $PARENT
docker build -t aixcc-dyva .
popd

RESOURCE_DIR=$CUR_DIR/resources/jenkins
mkdir -p $RESOURCE_DIR
pushd $RESOURCE_DIR

if [ ! -f $TARGET.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/$TARGET
    pushd $TARGET
    make cpsrc-prepare
    tar -cvzf ../$TARGET.tar.gz .
    popd
    rm -rf ./$TARGET
fi

popd
pdl --unlock || rm -rf pipeline.lock

pdl
TARGET_ID=1
OTHER_ID=222
pd inject dyva_locals.harness_info $OTHER_ID < $RESOURCE_DIR/harness_info.yaml
pd inject dyva_locals.target_metadata $TARGET_ID < $RESOURCE_DIR/target_metadata.yaml

pd inject dyva_locals.target_with_sources $TARGET_ID < "$RESOURCE_DIR/${TARGET}.tar.gz"
pd inject dyva_locals.crashing_input $OTHER_ID < $RESOURCE_DIR/crashing_seed
pd inject dyva_locals.point_of_interest $OTHER_ID < $RESOURCE_DIR/poi.yaml

ipython --pdb -- "$(which pd)" --verbose --debug-trace run
pd status
pd cat dyva_locals.logs $(pd ls dyva_locals.logs)
