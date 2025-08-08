#!/usr/bin/bash

set -e
set -x

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
TEST_DIR=$CUR_DIR/antlr4-test

TARGET="aixcc-sc-challenge-002-jenkins-plugins"

pushd $PARENT
docker build --no-cache -t aixcc-test_antlr_jenkins .
popd

mkdir -p $TEST_DIR
pushd $TEST_DIR

ls $TEST_DIR

if [ ! -f  aixcc-sc-challenge-002-jenkins-plugins.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-plugins.git
    pushd aixcc-sc-challenge-002-jenkins-plugins
    # make cpsrc-prepare
    echo "$(pwd)"
    tar -cvzf ../aixcc-sc-challenge-002-jenkins-plugins.tar.gz .
    popd
    rm -rf ./aixcc-sc-challenge-002-jenkins-plugins
fi
popd

pdl --unlock || rm -rf pipeline.lock

# ipython --pdb -- `which pdl`
pdl
pd inject antlr4_commit_java_parser.java_target_with_sources 1 < "${TEST_DIR}/${TARGET}.tar.gz"

ipython --pdb -- "$(which pd)" run --verbose --debug-trace
pd status

