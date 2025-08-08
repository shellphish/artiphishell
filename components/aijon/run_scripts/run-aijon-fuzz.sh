#!/bin/bash

set -e
set -u
set -x

export LANGUAGE=${LANGUAGE}
export HARNESS_NAME=${HARNESS_NAME}
export BUILD_SANITIZER=${BUILD_SANITIZER}
export INSTRUMENTATION_ARTIFACTS=${INSTRUMENTATION_ARTIFACTS}
export OSS_FUZZ_PROJECT_DIR=${OSS_FUZZ_PROJECT_DIR}
export DISCOVERY_GUY_CORPUS_DIR=${DISCOVERY_GUY_CORPUS_DIR:-""}

if [ "$LANGUAGE" == "jvm" ]; then
    INSTRUMENTATION="shellphish_jazzer"
elif [ "$LANGUAGE" == "c" ]; then
    INSTRUMENTATION="shellphish_aijon"
elif [ "$LANGUAGE" == "cpp" ]; then
    INSTRUMENTATION="shellphish_aijon"
else
    echo "Unsupported language: $LANGUAGE"
    exit 1
fi

if [ ! -d "$OSS_FUZZ_PROJECT_DIR/artifacts/out" ]; then
    echo "$OSS_FUZZ_PROJECT_DIR does not contain artifacts/out directory"
    exit 1
fi

# 🪩🕺
DISCO_DIR="$OSS_FUZZ_PROJECT_DIR/artifacts/work/discovery_guy_corpus"
mkdir -p $DISCO_DIR

if [ -n "$DISCOVERY_GUY_CORPUS_DIR" ]; then
    if [ ! -d "$DISCOVERY_GUY_CORPUS_DIR" ]; then
        echo "Discovery guy corpus directory does not exist: $DISCOVERY_GUY_CORPUS_DIR"
        exit 1
    fi
    rsync -ravz $DISCOVERY_GUY_CORPUS_DIR $DISCO_DIR
else
    echo "No discovery guy corpus directory specified, skipping copy."
fi

SEED_CORPUS_ZIP_FILE="${INSTRUMENTATION_ARTIFACTS}/${HARNESS_NAME}_seed_corpus.zip"
if [ -f "$SEED_CORPUS_ZIP_FILE" ]; then
    cp $SEED_CORPUS_ZIP_FILE $OSS_FUZZ_PROJECT_DIR/artifacts/out/
fi

oss-fuzz-fuzz \
    --build-runner-image \
    --sanitizer $BUILD_SANITIZER \
    --instrumentation $INSTRUMENTATION \
    --instance-name heck-${HARNESS_NAME} \
    --extra-env "DISCOVERY_GUY_CORPUS_DIR=/work/discovery_guy_corpus" \
    --extra-env "ARTIPHISHELL_IJON_MODE=1" \
    "$OSS_FUZZ_PROJECT_DIR" "$HARNESS_NAME"
