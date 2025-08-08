#!/bin/bash

set -e
set -u
set -x


export LANGUAGE=${LANGUAGE}
export PROJECT_ID=${PROJECT_ID}
export PROJECT_NAME=${PROJECT_NAME}
export CRS_TASK_ANALYSIS_SOURCE=${CRS_TASK_ANALYSIS_SOURCE}
export TARGET_FUNCTIONS_JSONS_DIR=${TARGET_FUNCTIONS_JSONS_DIR}
export FULL_FUNCTION_INDICES=${FULL_FUNCTION_INDICES}
export INSTRUMENTATION_ARTIFACTS=${INSTRUMENTATION_ARTIFACTS}

export POI_TYPE=${POI_TYPE}
export CODESWIPE_REPORT=${CODESWIPE_REPORT:-}
export DIFF_PATCH_FILE=${DIFF_PATCH_FILE:-}

export LOCAL_RUN=${LOCAL_RUN:-"0"}

if [ $POI_TYPE == "codeswipe" ]; then
    if [ -z "${CODESWIPE_REPORT}" ]; then
        echo "CODESWIPE_REPORT must be set when POI_TYPE is codeswipe"
        exit 1
    fi

    if [ "$LOCAL_RUN" -eq "1" ]; then
        python /aijon/main.py \
            --target_source ${CRS_TASK_ANALYSIS_SOURCE} \
            --target_functions_json_dir ${TARGET_FUNCTIONS_JSONS_DIR} \
            --full_function_indices ${FULL_FUNCTION_INDICES} \
            --codeswipe_report ${CODESWIPE_REPORT} \
            --destination ${INSTRUMENTATION_ARTIFACTS} \
            --diff_only
    else
        python /aijon/main.py \
            --target_source ${CRS_TASK_ANALYSIS_SOURCE} \
            --target_functions_json_dir ${TARGET_FUNCTIONS_JSONS_DIR} \
            --full_function_indices ${FULL_FUNCTION_INDICES} \
            --project_name ${PROJECT_NAME} \
            --project_id ${PROJECT_ID} \
            --codeswipe_report ${CODESWIPE_REPORT} \
            --destination ${INSTRUMENTATION_ARTIFACTS} \
            --diff_only
    fi

elif [ $POI_TYPE == "diff" ]; then
    if [ -z "${DIFF_PATCH_FILE}" ]; then
        echo "DIFF_PATCH_FILE must be set when POI_TYPE is diff"
        exit 1
    fi

    if [ "$LOCAL_RUN" -eq "1" ]; then
        python /aijon/main.py \
            --target_source ${CRS_TASK_ANALYSIS_SOURCE} \
            --target_functions_json_dir ${TARGET_FUNCTIONS_JSONS_DIR} \
            --full_function_indices ${FULL_FUNCTION_INDICES} \
            --patch_report ${DIFF_PATCH_FILE} \
            --destination ${INSTRUMENTATION_ARTIFACTS} \
            --diff_only
    else
        python /aijon/main.py \
            --target_source ${CRS_TASK_ANALYSIS_SOURCE} \
            --target_functions_json_dir ${TARGET_FUNCTIONS_JSONS_DIR} \
            --full_function_indices ${FULL_FUNCTION_INDICES} \
            --project_name ${PROJECT_NAME} \
            --project_id ${PROJECT_ID} \
            --patch_report ${DIFF_PATCH_FILE} \
            --destination ${INSTRUMENTATION_ARTIFACTS} \
            --diff_only
    fi

fi
