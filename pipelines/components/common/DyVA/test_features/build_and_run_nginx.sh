#!/usr/bin/bash
set -x

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
TARGET="targets-semis-aixcc-sc-challenge-004-nginx-cp"

pushd $PARENT
docker build -t aixcc-dyva .
popd

RESOURCE_DIR=$CUR_DIR/resources/nginx
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

if [ ! -d "nginx_dyva" ]; then
    tar -xvzf nginx_dyva.tar.gz
fi

popd

pdl --unlock || rm -rf pipeline.lock

pdl  --name dyva_reasoning
pd restore $RESOURCE_DIR/nginx_dyva --all
pd rm dyva_locals __all__
ipython --pdb -- "$(which pd)" --verbose --debug-trace -t dyva_reasoning run
pd status
pd cat dyva_reasoning.logs $(pd ls dyva_reasoning.logs)
