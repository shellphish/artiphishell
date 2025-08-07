#!/usr/bin/bash
set -x

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
TARGET="targets-semis-aixcc-sc-mock-cp"

pushd $PARENT
docker build -t aixcc-dyva .
popd

RESOURCE_DIR=$CUR_DIR/resources/mock-cp
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
SEED_ID=6a21f952c372514a5623e55700605492f74580ac0b08d552877f264d71c1ab37

pd inject dyva_reasoning.harness_info $OTHER_ID < $RESOURCE_DIR/harness_info.yaml
pd inject dyva_reasoning.target_metadata $TARGET_ID < $RESOURCE_DIR/target_metadata.yaml

pd inject dyva_reasoning.target_with_sources $TARGET_ID < "$RESOURCE_DIR/${TARGET}.tar.gz"
pd inject dyva_reasoning.crashing_input $SEED_ID < $RESOURCE_DIR/crashing_seed
pd inject dyva_reasoning.point_of_interest $OTHER_ID < $RESOURCE_DIR/poi.yaml

ipython --pdb -- "$(which pd)" --verbose --debug-trace run
pd status
pd cat dyva_reasoning.logs $(pd ls dyva_reasoning.logs)
