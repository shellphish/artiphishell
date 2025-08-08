#!/bin/bash
set -eux


# THESE VARIABLES ARE SET BY THE pipeline.yaml OR the run-from-backup.sh
# ==========================================================
export LOCAL_RUN="${LOCAL_RUN:-False}"
export PROJECT_ID=$PROJECT_ID
export TARGET_METADATA=$TARGET_METADATA
export FUNCTIONS_INDEX=$FUNCTIONS_INDEX
export TARGET_FUNCTIONS_JSONS_DIR=$TARGET_FUNCTIONS_JSONS_DIR
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO
export CODEQL_DB_PATH="${CODEQL_DB_PATH:-}"
export SCAN_GUY_RESULTS=${SCAN_GUY_RESULTS:-"/shared/scanguy_results"}
export VLLM_HOSTNAME="${VLLM_HOSTNAME:-http://vllm-server:25002/v1}"
# ==========================================================

# Create a temporary directory for the debug target
mkdir -p /shared/scanguy || true

# Wait for the vllm server to start

set +e

if [ "${LOCAL_RUN}" == "False" ]; then
    for i in {1..200}; do
        if curl "${VLLM_HOSTNAME%/}/completions" \
          -H "Content-Type: application/json" \
          -d '{
            "model": "/models/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100",
            "prompt": "CRS stands for ",
            "max_tokens": 8192,
            "temperature": 0
          }'; then
            echo "vllm server is up!"
            break
        fi
        echo "Attempt $i failed, retrying..."
        sleep 20
    done
fi

python /src/run.py \
    --project_id "${PROJECT_ID}" \
    --target_metadata "${TARGET_METADATA}" \
    --target_functions_jsons_dir "${TARGET_FUNCTIONS_JSONS_DIR}" \
    --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
    --function_index "${FUNCTIONS_INDEX}" \
    --codeql_db_path "${CODEQL_DB_PATH}" \
    --output_dir "${SCAN_GUY_RESULTS}" \
