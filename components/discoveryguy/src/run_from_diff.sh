#!/bin/bash
set -eu


# THESE VARIABLES ARE SET BY THE pipeline.yaml OR the run-from-backup.sh
# ==========================================================
export LOCAL_RUN=$LOCAL_RUN
export DISCO_GUY_FROM=$DISCO_GUY_FROM
export DELTA_MODE=$DELTA_MODE
export PROJECT_ID=$PROJECT_ID
export PROJECT_NAME=$PROJECT_NAME
export OSS_FUZZ_REPO_PATH=$OSS_FUZZ_REPO_PATH
export PROJECT_METADATA_PATH=$PROJECT_METADATA_PATH
export CRS_TASK_ANALYSIS_SOURCE=$CRS_TASK_ANALYSIS_SOURCE
export PROJECT_SOURCE=$CRS_TASK_ANALYSIS_SOURCE
export FUNCTIONS_BY_FILE_INDEX=$FUNCTIONS_BY_FILE_INDEX
export TARGET_METADATA=$TARGET_METADATA
export FUNCTIONS_INDEX=$FUNCTIONS_INDEX
export TARGET_FUNCTIONS_JSONS_DIR=$TARGET_FUNCTIONS_JSONS_DIR
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO
export CHANGED_FUNCTIONS_JSONS_DIR=$CHANGED_FUNCTIONS_JSONS_DIR
export CHANGED_FUNCTIONS_INDEX=$CHANGED_FUNCTIONS_INDEX
export DIFF_FILE=$DIFF_FILE
export BACKUP_SEEDS_VAULT=$BACKUP_SEEDS_VAULT
export REPORT_DIR=$REPORT_DIR
export CRASH_DIR_PASS_TO_POV=$CRASH_DIR_PASS_TO_POV
export CRASH_METADATA_DIR_PASS_TO_POV=$CRASH_METADATA_DIR_PASS_TO_POV
# ==========================================================

# Only for Local Runs
# if we are doing LOCAL_RUN we need to set 
if [ "$LOCAL_RUN" = "True" ]; then
    export DEBUG_BUILD_ARTIFACTS=$DEBUG_BUILD_ARTIFACTS
else
    # If we are not running locally, we will download the debug artifacts later
    export DEBUG_BUILD_ARTIFACTS=""
fi

# Create a temporary directory for the debug target
TARGET_SHARED_FOLDER="/shared/discoveryguy/${PROJECT_ID}/"
mkdir -p $TARGET_SHARED_FOLDER || true

#
# Visualization of the TEMPDIR folder:
# TL;DR; this is an oss-fuzz folder with the artifacts built
#        for debugging for the project under analysis
#        We are gonna use this for testing the POV discoveryguy will
#        generate.
# /shared/discoveryguy/
# ├── tmp919239193
#   │   ├── infra
#   │   ├── projects
#   │   │   └── nginx
#   │   │       ├── artifacts
#   │   │       |     ├── out
#   │   │       |     |    ├── pov_harness (with debugging)
#   │   │       |     |    ├── src
#   │   │       |     |         ├── Makefile
#   │   │       |     |         ├── ...
#   │   │       |     ├── work
#   │   │       |     ├── ...
#   |   |       ├── Dockerfile
#   |   |       ├── project.yaml
#   |   ├── ...
echo "Listing OSS_FUZZ_REPO_PATH: $OSS_FUZZ_REPO_PATH"
ls $OSS_FUZZ_REPO_PATH

# if we are doing a local run, we need to copy the debug builds
if [ "$LOCAL_RUN" = "True" ]; then
    echo "Listing DEBUG_BUILD_ARTIFACTS: $DEBUG_BUILD_ARTIFACTS"
    ls $DEBUG_BUILD_ARTIFACTS
    echo "Running rsync to copy debug artifacts..."
    ALL_DEBUG_BUILDS=$(mktemp -d -p $TARGET_SHARED_FOLDER)
    # Now, for every folder in DEBUG_BUILD_ARTIFACTS we are gonna create a 
    # new OSS_FUZZ_REPO_PATH that contains the debug artifacts
    # Remember, we have one debug build per sanitizer! (max 3 in c, 1 in java)
    for debug_build in $DEBUG_BUILD_ARTIFACTS/*; do
        if [ -d "$debug_build" ]; then
            echo "Processing debug build $debug_build"
            build_config_id=$(basename $debug_build)
            TMPDIR=$ALL_DEBUG_BUILDS/$build_config_id
            mkdir "$TMPDIR"
            # Copy the entire OSS_FUZZ_REPO_PATH structure to the temp dir
            rsync -ra "$OSS_FUZZ_REPO_PATH"/ ${TMPDIR}/
            # Now copy the specific debug build artifacts into the right place
            rsync -ra "$debug_build"/* "$TMPDIR"/projects/$PROJECT_NAME
            echo "Debug build artifacts copied to: $TMPDIR/projects/$PROJECT_NAME"
        fi
    done
else
    echo "Not running in local mode, the debug artifacts will be downloaded later!"
    ALL_DEBUG_BUILDS=$(mktemp -d -p $TARGET_SHARED_FOLDER)
fi

if [ "$LOCAL_RUN" != "False" ]; then
cat <<EOF > ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh
#!/bin/bash

set -eux
rm -rf /tmp/stats/*
export LITELLM_KEY=$LITELLM_KEY
export AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME
export USE_LLM_API=$USE_LLM_API
export ANALYSIS_GRAPH_BOLT_URL=$ANALYSIS_GRAPH_BOLT_URL
export CODEQL_SERVER_URL=$CODEQL_SERVER_URL
export FUNC_RESOLVER_URL=$FUNC_RESOLVER_URL
export PROJECT_ID=$PROJECT_ID
export PROJECT_NAME=$PROJECT_NAME
export DELTA_MODE=$DELTA_MODE
export DISCO_GUY_FROM=$DISCO_GUY_FROM
export LOCAL_RUN=$LOCAL_RUN

echo "*****************************************"
echo "STARTING DISCOVERY GUY FROM ONLYDIFF!"
echo "*****************************************"


if [ "$DELTA_MODE" = "True" ]; then
    export CHANGED_FUNCTIONS_JSONS_DIR=$CHANGED_FUNCTIONS_JSONS_DIR
    export CHANGED_FUNCTIONS_INDEX=$CHANGED_FUNCTIONS_INDEX
    export DIFF_FILE=$DIFF_FILE
fi

# If we are running in DELTA_MODE we are passing also the diffguy information
python -u /src/run.py \
    --project_id "${PROJECT_ID}" \
    --dg_id 1 \
    --project_source "${PROJECT_SOURCE}" \
    --oss_fuzz_debug_targets_folder "${ALL_DEBUG_BUILDS}" \
    --target_metadata "${TARGET_METADATA}" \
    --target_functions_jsons_dir "${TARGET_FUNCTIONS_JSONS_DIR}" \
    --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
    --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
    --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
    --function_index "${FUNCTIONS_INDEX}" \
    --changed_function_index "${CHANGED_FUNCTIONS_INDEX}" \
    --diff_file "${DIFF_FILE}" \
    --backup_seeds_vault "${BACKUP_SEEDS_VAULT}" \
    --report_dir "${REPORT_DIR}" \
    --crash_dir_pass_to_pov "${CRASH_DIR_PASS_TO_POV}" \
    --crash_metadata_dir_pass_to_pov "${CRASH_METADATA_DIR_PASS_TO_POV}"
EOF

chmod +x ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh

fi

echo "*****************************************"
echo "STARTING DISCOVERY GUY FROM ONLYDIFF!    "
echo "*****************************************"


# If we are running in DELTA_MODE we are passing also the diffguy information
if [ "$DELTA_MODE" == "True" ]; then
    python -u /src/run.py \
        --project_id "${PROJECT_ID}" \
        --dg_id 1 \
        --project_source "${PROJECT_SOURCE}" \
        --oss_fuzz_repo_path "${OSS_FUZZ_REPO_PATH}" \
        --oss_fuzz_debug_targets_folder "${ALL_DEBUG_BUILDS}" \
        --target_metadata "${TARGET_METADATA}" \
        --target_functions_jsons_dir "${TARGET_FUNCTIONS_JSONS_DIR}" \
        --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
        --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --function_index "${FUNCTIONS_INDEX}" \
        --changed_function_index "${CHANGED_FUNCTIONS_INDEX}" \
        --diff_file "${DIFF_FILE}" \
        --backup_seeds_vault "${BACKUP_SEEDS_VAULT}" \
        --report_dir "${REPORT_DIR}" \
        --crash_dir_pass_to_pov "${CRASH_DIR_PASS_TO_POV}" \
        --crash_metadata_dir_pass_to_pov "${CRASH_METADATA_DIR_PASS_TO_POV}"
else
    echo "Running in non-delta mode, but this is not supported by run_from_diff.sh. Aborting."
    exit 1
fi

