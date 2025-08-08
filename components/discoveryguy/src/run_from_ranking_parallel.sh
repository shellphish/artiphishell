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
export FUNC_RANKING=$FUNC_RANKING
export POIS=$POIS
export CODEQL_DB_PATH="${CODEQL_DB_PATH:-}"
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

NUM_PROCESSES=2

# Create a temporary directory for the debug target
TARGET_SHARED_FOLDER="/shared/discoveryguy/${PROJECT_ID}/"
mkdir -p $TARGET_SHARED_FOLDER || true


# Iterate for NUM_PROCESSES

for i in $(seq 1 $NUM_PROCESSES); do

export NUM_PROCESS=$i

# if we are doing a local run, we need to copy the debug builds
if [ "$LOCAL_RUN" = "True" ]; then
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
    OSS_FUZZ_REPO_PATH_COPY=$(mktemp -d -p $TARGET_SHARED_FOLDER)
    rsync -ra "$OSS_FUZZ_REPO_PATH"/ ${OSS_FUZZ_REPO_PATH_COPY}/
    OSS_FUZZ_REPO_PATH=${OSS_FUZZ_REPO_PATH_COPY}
    ALL_DEBUG_BUILDS=$(mktemp -d -p $TARGET_SHARED_FOLDER)
fi

echo "*************************************************"
echo "STARTING DISCOVERY GUY PARALLEL FROM CODEQL POIS!"
echo "*************************************************"

# NOTES FOR PARALLEL VERSION
# - self.project_source is OK to be shared, the folder is used only for read-only (grep) operations
# - oss_fuzz_coverage_target_folder is copied PER process
# - self.target_metadata is OK to be shared, the file is used only for read-only (grep) operations
# - self.target_functions_jsons_dir is OK to be shared, the folder is used only for read-only (grep) operations
# - self.aggregated_harness_info_file is OK to be shared, the file is used only for read-only (grep) operations
# - self.functions_by_file_index is OK to be shared, the file is used only for read-only (grep) operations
# - self.function_index is OK to be shared, the file is used only for read-only (grep) operations
# - self.function_ranking is the chunked by the split_func_ranking script
# - self.codeql_db_path is OK to be shared, in local mode we will only upload once
# - self.pois is OK to be shared, the file is used only for read-only (grep) operations
# - self.changed_functions_jsons_dir is OK to be shared, the folder is used only for read-only (grep) operations
# - self.changed_function_index is OK to be shared, the file is used only for read-only (grep) operations
# - self.diff_file is OK to be shared, the file is used only for read-only (grep) operations
# - self.backup_seeds_vault is OK to be shared, multiple discoveryguy will drop their seeds there
# - self.crash_dir_pass_to_pov is OK to be shared, this is the sync folder for povguy
# - self.crash_metadata_dir_pass_to_pov is OK to be shared, this is the sync folder for povguy

# If the NUM_PROCESS is 1, we are not splitting the function ranking
if [ "$NUM_PROCESSES" -eq 1 ]; then
    echo "Running in single process mode, not splitting the function ranking."
else
    echo "Running in parallel mode, splitting the function ranking."
    python /src/split_func_ranking.py --num_proc $NUM_PROCESSES --proc_id $i --func_ranking "${FUNC_RANKING}" --output /tmp/func_ranking_split-$i.json
    export SPLIT_FUNC_RANKING="/tmp/func_ranking_split-$i.json"
fi

echo "#############################"
echo $SPLIT_FUNC_RANKING
cat $SPLIT_FUNC_RANKING
echo "#############################"

# If we are running in DELTA_MODE we are passing also the diffguy information
if [ "$DELTA_MODE" == "True" ]; then
    python -u /src/run.py \
        --project_id "${PROJECT_ID}" \
        --dg_id "${NUM_PROCESS}" \
        --project_source "${PROJECT_SOURCE}" \
        --oss_fuzz_repo_path "${OSS_FUZZ_REPO_PATH}" \
        --oss_fuzz_debug_targets_folder "${ALL_DEBUG_BUILDS}" \
        --target_metadata "${TARGET_METADATA}" \
        --target_functions_jsons_dir "${TARGET_FUNCTIONS_JSONS_DIR}" \
        --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
        --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --function_index "${FUNCTIONS_INDEX}" \
        --function_ranking "${SPLIT_FUNC_RANKING}" \
        --codeql_db_path "${CODEQL_DB_PATH}" \
        --pois "${POIS}" \
        --changed_function_index "${CHANGED_FUNCTIONS_INDEX}" \
        --diff_file "${DIFF_FILE}" \
        --backup_seeds_vault "${BACKUP_SEEDS_VAULT}" \
        --report_dir "${REPORT_DIR}" \
        --crash_dir_pass_to_pov "${CRASH_DIR_PASS_TO_POV}" \
        --crash_metadata_dir_pass_to_pov "${CRASH_METADATA_DIR_PASS_TO_POV}" &
else

    python -u /src/run.py \
        --project_id "${PROJECT_ID}" \
        --dg_id "${NUM_PROCESS}" \
        --oss_fuzz_repo_path "${OSS_FUZZ_REPO_PATH}" \
        --oss_fuzz_debug_targets_folder "${ALL_DEBUG_BUILDS}" \
        --project_source "${PROJECT_SOURCE}" \
        --target_metadata "${TARGET_METADATA}" \
        --target_functions_jsons_dir "${TARGET_FUNCTIONS_JSONS_DIR}" \
        --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --function_index "${FUNCTIONS_INDEX}" \
        --function_ranking "${SPLIT_FUNC_RANKING}" \
        --codeql_db_path "${CODEQL_DB_PATH}" \
        --pois "${POIS}" \
        --backup_seeds_vault "${BACKUP_SEEDS_VAULT}" \
        --report_dir "${REPORT_DIR}" \
        --crash_dir_pass_to_pov "${CRASH_DIR_PASS_TO_POV}" \
        --crash_metadata_dir_pass_to_pov "${CRASH_METADATA_DIR_PASS_TO_POV}" &
fi

done

# Wait for all background processes to finish
wait
echo "*****************************************"
echo "ALL DISCOVERY GUY PROCESSES FINISHED!"
echo "*****************************************"