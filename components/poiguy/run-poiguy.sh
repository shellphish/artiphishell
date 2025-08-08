#!/bin/bash

set -x
set -e
set -u

export PROJECT_ID="$PROJECT_ID"
export PROJECT_METADATA_PATH="$PROJECT_METADATA_PATH"
export POV_REPORT_ID="$POV_REPORT_ID"
export POV_REPORT_PATH="$POV_REPORT_PATH"

export POI_REPORTS_DIR="$POI_REPORTS_DIR"

mkdir -p /tmp/pois

python3 /poiguy/poiguy.py \
        --project-id $PROJECT_ID \
        --report $POV_REPORT_PATH \
        --report-id $POV_REPORT_ID \
        --project-metadata $PROJECT_METADATA_PATH \
        --output $POI_REPORTS_DIR