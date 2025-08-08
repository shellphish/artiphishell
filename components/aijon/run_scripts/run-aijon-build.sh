#!/bin/bash

set -e
set -u
set -x

export LANGUAGE=${LANGUAGE}
export PROJECT_ID=${PROJECT_ID}
export AFL_ALLOW_LIST=${AFL_ALLOW_LIST}
export BUILD_ARTIFACTS=${BUILD_ARTIFACTS}
export BUILD_SANITIZER=${BUILD_SANITIZER}
export BUILD_PATCH_FILE=${BUILD_PATCH_FILE}
export BUILD_ARCHITECTURE=${BUILD_ARCHITECTURE}
export OSS_FUZZ_PROJECT_DIR=${OSS_FUZZ_PROJECT_DIR}
export CRS_TASK_ANALYSIS_SOURCE=${CRS_TASK_ANALYSIS_SOURCE}
export INSTRUMENTATION_ARTIFACTS=${INSTRUMENTATION_ARTIFACTS}

if [ "$LANGUAGE" == "jvm" ]; then
    INSTRUMENTATION="shellphish_jazzer"
elif [ "$LANGUAGE" == "c" ]; then
    INSTRUMENTATION="shellphish_aijon"
elif [ "$LANGUAGE" == "c++" ]; then
    INSTRUMENTATION="shellphish_aijon"
else
    echo "Unsupported language: $LANGUAGE"
    exit 1
fi

if [ ! -f "$BUILD_PATCH_FILE" ]; then
    echo "BUILD_PATCH_FILE not found: $BUILD_PATCH_FILE"
    exit 1
fi

if [ ! -f "$AFL_ALLOW_LIST" ]; then
    echo "AFL_ALLOW_LIST file not found: $AFL_ALLOW_LIST"
    exit 1
fi

BUILD_IMAGE_COMMAND="oss-fuzz-build-image --instrumentation $INSTRUMENTATION $OSS_FUZZ_PROJECT_DIR"
# if IN_K8S is set, add --push
if [ ! -z "${IN_K8S:-}" ]; then
    BUILD_IMAGE_COMMAND="$BUILD_IMAGE_COMMAND --push"
fi

BUILDER_IMAGE=$($BUILD_IMAGE_COMMAND | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$BUILDER_IMAGE" ]; then exit 1; fi
RUNNER_IMAGE=$($BUILD_IMAGE_COMMAND --build-runner-image | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$RUNNER_IMAGE" ]; then exit 1; fi

# Dry run
set +e
if [ ! -z "${IN_PIPELINE:-}" ]; then
    BUILD_OUTPUT=$(oss-fuzz-build \
        --use-task-service \
        --project-id $PROJECT_ID \
        --sanitizer $BUILD_SANITIZER \
        --architecture $BUILD_ARCHITECTURE \
        --instrumentation $INSTRUMENTATION \
        --project-source $CRS_TASK_ANALYSIS_SOURCE \
        --cpu ${INITIAL_BUILD_CPU:-6} \
        --mem ${INITIAL_BUILD_MEM:-26Gi} \
        --max-cpu ${INITIAL_BUILD_MAX_CPU:-10} \
        --max-mem ${INITIAL_BUILD_MAX_MEM:-40Gi} \
        "$OSS_FUZZ_PROJECT_DIR")
    RET_CODE=$?
else
    # HECK THE TASK SERVICE
    BUILD_OUTPUT=$(oss-fuzz-build \
        --project-id $PROJECT_ID \
        --sanitizer $BUILD_SANITIZER \
        --architecture $BUILD_ARCHITECTURE \
        --instrumentation $INSTRUMENTATION \
        --project-source $CRS_TASK_ANALYSIS_SOURCE \
        "$OSS_FUZZ_PROJECT_DIR")
    RET_CODE=$?
fi

if [ "$RET_CODE" -ne 0 ]; then
    STDERR_FILE=$(echo $BUILD_OUTPUT |grep -oP 'stderr log: \K.*')
    echo "Building the target failed even without patches"
    echo "Error log in $STDERR_FILE"
    exit 1
fi

BUILD_OUTPUT_FILE=$(mktemp /tmp/aijon_build.XXXXXX)
if [ ! -z "${IN_PIPELINE:-}" ]; then
    # the task service for building already handles the pulling of the project_analysis_sources so we don't
    # need to do anything with those here
    oss-fuzz-build \
        --use-task-service \
        --project-id $PROJECT_ID \
        --sanitizer $BUILD_SANITIZER \
        --patch-path $BUILD_PATCH_FILE \
        --architecture $BUILD_ARCHITECTURE \
        --instrumentation $INSTRUMENTATION \
        --project-source $CRS_TASK_ANALYSIS_SOURCE \
        --extra-file "$AFL_ALLOW_LIST:/out/aijon_allowlist.txt" \
        --extra-env "AFL_ALLOW_LIST=/out/aijon_allowlist.txt" \
        --cpu ${INITIAL_BUILD_CPU:-6} \
        --mem ${INITIAL_BUILD_MEM:-26Gi} \
        --max-cpu ${INITIAL_BUILD_MAX_CPU:-10} \
        --max-mem ${INITIAL_BUILD_MAX_MEM:-40Gi} \
        "$OSS_FUZZ_PROJECT_DIR" > $BUILD_OUTPUT_FILE
    RET_CODE=$?
else
    # HECK THE TASK SERVICE
    oss-fuzz-build \
        --project-id $PROJECT_ID \
        --sanitizer $BUILD_SANITIZER \
        --patch-path $BUILD_PATCH_FILE \
        --architecture $BUILD_ARCHITECTURE \
        --instrumentation $INSTRUMENTATION \
        --project-source $CRS_TASK_ANALYSIS_SOURCE \
        --extra-file "$AFL_ALLOW_LIST:/out/aijon_allowlist.txt" \
        --extra-env "AFL_ALLOW_LIST=/out/aijon_allowlist.txt" \
        "$OSS_FUZZ_PROJECT_DIR" > $BUILD_OUTPUT_FILE
    RET_CODE=$?
fi

CTR=0
while [ "$RET_CODE" -ne 0 ]; do
    if [ $CTR -eq 10 ]; then
        echo "Could not successfully compile after 10 iterations. Giving up"
        exit 1
    fi
    CTR=$(($CTR+1))

    STDERR_FILE=$(grep -oP 'stderr log: \K.*' $BUILD_OUTPUT_FILE)
    if [ "$INSTRUMENTATION" == "shellphish_jazzer" ]; then
        STDOUT_FILE=$(grep -oP 'stdout log: \K\S+stderr\.log' $BUILD_OUTPUT_FILE)
        if [[ -z "$STDOUT_FILE" ]] || [[ "$STDOUT_FILE" == "None" ]] || [[ ! -f "$STDOUT_FILE" ]]; then
            echo "No stdout log found in build output. Parsing from build output"
            STDOUT_FILE=$(mktemp /tmp/aijon_stdout.XXXXXX)
	    STDERR_FILE=$(mktemp /tmp/aijon_stderr.XXXXXX)
            sed -n '/Stdout:/,/Stderr:/p' > "$STDOUT_FILE" < $BUILD_OUTPUT_FILE
        fi
        grep 'ERROR' $STDOUT_FILE > $STDERR_FILE

    else
        if [[ -z "$STDERR_FILE" ]] || [[ "$STDERR_FILE" == "None" ]] || [[ ! -f "$STDERR_FILE" ]]; then
            echo "No stderr log found in build output. Parsing from build output"
            STDERR_FILE=$(mktemp /tmp/aijon_stderr.XXXXXX)
            sed -n '/Stderr:/,/Container ID:/p' > "$STDERR_FILE" < $BUILD_OUTPUT_FILE
        fi
	cp $STDERR_FILE /tmp/aijon_tmp_stderr
	grep '[Ee]rror:' -B5 -A5 /tmp/aijon_tmp_stderr > "$STDERR_FILE"
    fi

    TEMP_DIR=$(mktemp -d)

    python /aijon/fixer.py \
        --target_source $CRS_TASK_ANALYSIS_SOURCE \
        --patch_path $BUILD_PATCH_FILE \
        --stderr_log $STDERR_FILE \
        --destination $TEMP_DIR

    BUILD_PATCH_FILE="$TEMP_DIR/aijon_instrumentation.patch"
    if [ ! -f "$BUILD_PATCH_FILE" ]; then
        echo "BUILD_PATCH_FILE not found after running fixer"
        exit 1
    fi

    if [ ! -z "${IN_PIPELINE:-}" ]; then
        oss-fuzz-build \
            --use-task-service \
            --project-id $PROJECT_ID \
            --sanitizer $BUILD_SANITIZER \
            --patch-path $BUILD_PATCH_FILE \
            --architecture $BUILD_ARCHITECTURE \
            --instrumentation $INSTRUMENTATION \
            --project-source $CRS_TASK_ANALYSIS_SOURCE \
            --extra-file "$AFL_ALLOW_LIST:/out/aijon_allowlist.txt" \
            --extra-env "AFL_ALLOW_LIST=/out/aijon_allowlist.txt" \
            --cpu ${INITIAL_BUILD_CPU:-6} \
            --mem ${INITIAL_BUILD_MEM:-26Gi} \
            --max-cpu ${INITIAL_BUILD_MAX_CPU:-10} \
            --max-mem ${INITIAL_BUILD_MAX_MEM:-40Gi} \
            "$OSS_FUZZ_PROJECT_DIR" > $BUILD_OUTPUT_FILE
        RET_CODE=$?
    else
        # HECK THE TASK SERVICE
        oss-fuzz-build \
            --project-id $PROJECT_ID \
            --sanitizer $BUILD_SANITIZER \
            --patch-path $BUILD_PATCH_FILE \
            --architecture $BUILD_ARCHITECTURE \
            --instrumentation $INSTRUMENTATION \
            --project-source $CRS_TASK_ANALYSIS_SOURCE \
            --extra-file "$AFL_ALLOW_LIST:/out/aijon_allowlist.txt" \
            --extra-env "AFL_ALLOW_LIST=/out/aijon_allowlist.txt" \
            "$OSS_FUZZ_PROJECT_DIR" > $BUILD_OUTPUT_FILE
        RET_CODE=$?
    fi
done
set -e

echo "${BUILDER_IMAGE}" >> "${OSS_FUZZ_PROJECT_DIR}/artifacts/builder_image"
echo "${RUNNER_IMAGE}" >> "${OSS_FUZZ_PROJECT_DIR}/artifacts/runner_image"

num_seed_corpus=$(ls $INSTRUMENTATION_ARTIFACTS/ | grep '_seed_corpus.zip$' | wc -l)
if [ "$num_seed_corpus" -gt 0 ]; then
    find $INSTRUMENTATION_ARTIFACTS -maxdepth 1 -type f -name "*_seed_corpus.zip" | while read -r line; do
        num_seeds=$(zipinfo -1 $line |grep -v '/$'|wc -l)
        if [ "$num_seeds" -gt 0 ]; then
            cp "$line" "$OSS_FUZZ_PROJECT_DIR/artifacts/out/"
        fi
    done
fi

if [ "$LANGUAGE" == "jvm" ]; then
    cp /aijon/IJONJava.java "$OSS_FUZZ_PROJECT_DIR/artifacts/out/"
fi

rsync -ra "$OSS_FUZZ_PROJECT_DIR"/ ${BUILD_ARTIFACTS}/
