#!/bin/bash

set -eux

# TODO: Exports these variables in the pipeline.yaml and 
#       call this script from there
python /src/invguy.py \
    --target-dir "${TARGET_BUILT_WITH_INSTRUMENTATION}" \
    --target-metadata "${TARGET_METADATA}" \
    --benign-inputs "${SIMILAR_HARNESS_INPUT_DIR}" \
    --crash-input "${REPRESENTATIVE_CRASHING_HARNESS_INPUT}" \
    --crash-commit "${CRASHING_COMMIT}" \
    --poiguy-report "${POI_REPORT}" \
    --functions_by_file_index "${FUNCTION_BY_FILE_INDEX_REPORT}" \
    --output-report-at "${OUT_REPORT_AT}" \
    --num-benign-min 1
