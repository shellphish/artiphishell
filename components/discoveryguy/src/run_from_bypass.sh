#!/bin/bash
set -eu


# THESE VARIABLES ARE SET BY THE pipeline.yaml OR the run-from-backup.sh
# ==========================================================
export LOCAL_RUN=$LOCAL_RUN
export DELTA_MODE=False
export DISCO_GUY_FROM=$DISCO_GUY_FROM
export PROJECT_ID=$PROJECT_ID
export PROJECT_NAME=$PROJECT_NAME
export OSS_FUZZ_REPO_PATH=$OSS_FUZZ_REPO_PATH
export PROJECT_SOURCE=$CRS_TASK_ANALYSIS_SOURCE
export PATCHED_BUILD_ARTIFACT=$PATCHED_BUILD_ARTIFACT
export TARGET_METADATA=$TARGET_METADATA
export PATCH_ID=$PATCH_ID
export PATCH_BYPASS_META=$PATCH_BYPASS_META
export BYPASS_RESULT_DIR=$BYPASS_RESULT_DIR
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO
export CRASH_DIR_PASS_TO_POV=$CRASH_DIR_PASS_TO_POV
export CRASH_METADATA_DIR_PASS_TO_POV=$CRASH_METADATA_DIR_PASS_TO_POV
export DEBUG_BUILD_ARTIFACT=$DEBUG_BUILD_ARTIFACT
# ==========================================================


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
echo "Listing PATCHED_BUILD_ARTIFACT: $PATCHED_BUILD_ARTIFACT"
ls $PATCHED_BUILD_ARTIFACT
echo "Running rsync to copy patched artifacts...============================"
TMPDIR=$(mktemp -d -p $TARGET_SHARED_FOLDER)
rsync -ra "$OSS_FUZZ_REPO_PATH"/ ${TMPDIR}/
rm -rf "$TMPDIR"/projects/$PROJECT_NAME/artifacts/ || true
rsync -ra $PATCHED_BUILD_ARTIFACT/* "$TMPDIR"/projects/$PROJECT_NAME/artifacts/

# lets make a copy of the debug_build_artifact
echo "Listing DEBUG_BUILD_ARTIFACT: $DEBUG_BUILD_ARTIFACT"
ls $DEBUG_BUILD_ARTIFACT
echo "Running rsync to copy debug artifacts...============================"
TMPDIR_TWO=$(mktemp -d -p $TARGET_SHARED_FOLDER)
rsync -ra "$OSS_FUZZ_REPO_PATH"/ ${TMPDIR_TWO}/
rsync -ra $DEBUG_BUILD_ARTIFACT/* "$TMPDIR_TWO"/projects/$PROJECT_NAME

# Make a copy of the project source code for applying the patch later
TMPDIR_THREE=$(mktemp -d -p $TARGET_SHARED_FOLDER)
rsync -ra "$PROJECT_SOURCE"/ ${TMPDIR_THREE}/

echo "PROJECT-DEBUG AT ARTIFACTS: $TMPDIR"

OSS_FUZZ_REPO_PATH_DEBUG="${TMPDIR}"
DEBUG_BUILD_ARTIFACT="${TMPDIR_TWO}"
PROJECT_SOURCE="${TMPDIR_THREE}"



echo "*****************************************"
echo "STARTING DISCOVERY GUY FROM BYPASS!"
echo "*****************************************"

python -u /src/run.py \
    --project_id "${PROJECT_ID}" \
    --dg_id 1 \
    --project_source "${PROJECT_SOURCE}" \
    --oss_fuzz_debug_target_folder "${OSS_FUZZ_REPO_PATH_DEBUG}/projects/$PROJECT_NAME/" \
    --target_metadata "${TARGET_METADATA}" \
    --aggregated_harness_info_file "${AGGREGATED_HARNESS_INFO}" \
    --patch_id "${PATCH_ID}" \
    --bypass_request "${PATCH_BYPASS_META}" \
    --bypass_result_dir "${BYPASS_RESULT_DIR}" \
    --crash_dir_pass_to_pov "${CRASH_DIR_PASS_TO_POV}" \
    --crash_metadata_dir_pass_to_pov "${CRASH_METADATA_DIR_PASS_TO_POV}" \
    --debug_build_artifact "${DEBUG_BUILD_ARTIFACT}/projects/$PROJECT_NAME/"


