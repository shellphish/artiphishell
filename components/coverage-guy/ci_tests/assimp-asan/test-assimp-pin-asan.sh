#!/bin/bash -u
# import shutil
set -eux

CURR_DIR=$(pwd)

WORKDIR=/shared/ci_tests/
mkdir -p $WORKDIR

SEEDS=/shared/ci_tests/seeds/
mkdir -p $SEEDS

cd $WORKDIR && git clone https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets || true
cd $WORKDIR && git clone https://github.com/shellphish-support-syndicate/shellphish-assimp || true

cd $CURR_DIR

cp /shellphish/coverageguy/ci_tests/assimp/assimp-seeds/* $SEEDS


OSS_FUZZ_TARGET_REPO=/shared/ci_tests/artiphishell-ossfuzz-targets/projects/assimp
TARGET_SRC=/shared/ci_tests/shellphish-assimp

export OSS_FUZZ_TARGET_REPO=$OSS_FUZZ_TARGET_REPO
export TARGET_SRC=$TARGET_SRC
export SEEDS=$SEEDS

#rm -rf $OSS_FUZZ_TARGET_REPO/artifacts/

# Build the target with coverage if the binary does not exists yet
if [ ! -f $OSS_FUZZ_TARGET_REPO/artifacts/out/assimp_fuzzer -o ! -f $OSS_FUZZ_TARGET_REPO-asan/artifacts/out/assimp_fuzzer ]; then
    echo "Building the target with ASAN"
    cd $OSS_FUZZ_TARGET_REPO
    oss-fuzz-build $OSS_FUZZ_TARGET_REPO --sanitizer=address --instrumentation=libfuzzer --architecture=x86_64 --project-source $TARGET_SRC
    cp -r $OSS_FUZZ_TARGET_REPO $OSS_FUZZ_TARGET_REPO-asan
    echo "Building the target with COVERAGE"
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

python3 /shellphish/coverageguy/ci_tests/assimp-asan/test-assimp-pin-asan.py 