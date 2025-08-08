#!/bin/bash

set -ux

# Supress warnings about raw docker usage
export ALLOW_RAW_DOCKER_USAGE=1

export POI_REPORT="$POI_REPORT"
export DYVA_BUILD_ARTIFACT="$DYVA_BUILD_ARTIFACT"
export CRASHING_INPUT="$CRASHING_INPUT" 
export OSS_FUZZ_PROJECT="$OSS_FUZZ_PROJECT"
export PROJECT_METADATA="$PROJECT_METADATA"
export CRS_TASK_ID="${CRS_TASK_ID:-all}"

export LOCAL_VARIABLE_REPORT="$LOCAL_VARIABLE_REPORT"

PROJECT_NAME=$(yq .shellphish.project_name $PROJECT_METADATA)

DYVA_SHARED_DIR="/shared/dyva/${CRS_TASK_ID}"
mkdir -p ${DYVA_SHARED_DIR}/oss_fuzz
TMP_DIR=$(mktemp -d -p ${DYVA_SHARED_DIR}/oss_fuzz/)
SHARED_OSS_FUZZ_PROJECT=$TMP_DIR
rsync -ra ${OSS_FUZZ_PROJECT}/* ${SHARED_OSS_FUZZ_PROJECT}

PROJECT_DIR=${SHARED_OSS_FUZZ_PROJECT}/projects/${PROJECT_NAME}
rsync -ra ${DYVA_BUILD_ARTIFACT}/* ${PROJECT_DIR}/artifacts

export PYTHONBUFFERED=0
export PYTHONBREAKPOINT=ipdb.set_trace

timeout 960 python /app/dyva/run.py \
                  --oss-fuzz-project $PROJECT_DIR \
                  --crashing-input $CRASHING_INPUT \
                  --poi-report $POI_REPORT \
                  --output-path $LOCAL_VARIABLE_REPORT

if [ ! -s $LOCAL_VARIABLE_REPORT ]; then
    DEBUG_LIB_PATH=$(python -c "import debug_lib; import os; print(os.path.dirname(debug_lib.__file__))")
    cat "${DEBUG_LIB_PATH}/agent/prompts/example_root_cause.yaml" | yq '.errored = true | .found_root_cause = false' > $LOCAL_VARIABLE_REPORT
fi

cat $LOCAL_VARIABLE_REPORT