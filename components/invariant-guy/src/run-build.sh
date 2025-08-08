#!/bin/bash

set -eux

# TODO: Exports these variables in the pipeline.yaml and 
#       call this script from there
python /src/invguy-build.py \
    --target-dir "${TARGET_FOLDER}" \
    --target-metadata "${TARGET_METADATA}" \
    --project-id "${PROJECT_ID}" \
    --target-built "${CP_FOLDER_BUILT}"