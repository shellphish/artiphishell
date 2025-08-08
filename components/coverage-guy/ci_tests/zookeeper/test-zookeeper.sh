

#!/bin/bash -u

set -eux

CURR_DIR=$(pwd)

WORKDIR=/shared/ci_tests/
mkdir -p $WORKDIR

SEEDS=/shared/ci_tests/seeds/
mkdir -p $SEEDS

cd $WORKDIR && git clone https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets || true
cd $WORKDIR && git clone https://github.com/shellphish-support-syndicate/afc-round-1-zookeeper || true

cd $CURR_DIR
cp /shellphish/coverageguy/ci_tests/zookeeper/zookeeper-seeds/* $SEEDS

OSS_FUZZ_TARGET_REPO=/shared/ci_tests/artiphishell-ossfuzz-targets/projects/zookeeper
TARGET_SRC=/shared/ci_tests/afc-round-1-zookeeper

export OSS_FUZZ_TARGET_REPO=$OSS_FUZZ_TARGET_REPO
export TARGET_SRC=$TARGET_SRC
export SEEDS=$SEEDS

# Build the target with coverage if the fuzz_cups binary does not exists yet
if [ ! -f $OSS_FUZZ_TARGET_REPO/artifacts/out/Zip4jFuzzer ]; then
    echo "Building the target with coverage"
    cd $OSS_FUZZ_TARGET_REPO
    oss-fuzz-build $OSS_FUZZ_TARGET_REPO --sanitizer=coverage --instrumentation=coverage_fast --architecture=x86_64 --project-source $TARGET_SRC
    if [ $? -ne 0 ]; then
        echo "Failed to build the target with coverage"
        exit 1
    fi
fi

# Check the exit code of the oss-fuzz-build
if [ $? -ne 0 ]; then
    echo "Failed to build the target with coverage"
    exit 1
fi

python3 /shellphish/coverageguy/ci_tests/zookeeper/test-zookeeper.py 