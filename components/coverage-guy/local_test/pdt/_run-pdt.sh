#!/bin/bash

set -xe

# needed links:
#   harness_info_id:
#     repo: project_harness_infos
#     kind: InputId
#   harness_info_meta:
#     repo: project_harness_infos
#     kind: InputMetadata
#   harness_info:
#     repo: project_harness_infos
#     kind: InputFilepath
#   oss_fuzz_project:
#     repo: crs_tasks_oss_fuzz_repos
#     kind: InputFilepath
#     key: harness_info_meta.project_id
#   coverage_build_artifact:
#     repo: coverage_build_artifacts
#     kind: InputFilepath
#     key: harness_info_meta.project_id
#   project_metadata:
#     repo: project_metadatas
#     kind: InputMetadata
#     key: harness_info_meta.project_id
#   project_id:
#     repo: project_metadatas
#     kind: InputId
#     key: harness_info_meta.project_id
#   project_cancel:
#     repo: crs_tasks_cancelled
#     kind: Cancel
#     key: harness_info_meta.project_id
#   project_metadata_path:
#     repo: project_metadatas
#     kind: InputFilepath
#     key: harness_info_meta.project_id
#   functions_index:
#     repo: full_functions_indices
#     kind: InputFilepath
#     key: harness_info_meta.project_id
#   functions_jsons_dir:
#     repo: full_functions_jsons_dirs
#     kind: InputFilepath
#     key: harness_info_meta.project_id
#   benign_harness_inputs_metadata_filtering_scope:
#     repo: benign_harness_inputs_metadatas
#     kind: null
#   benign_harness_inputs:
#     repo: benign_harness_inputs
#     kind: StreamingInputFilepath
#     key: benign_harness_inputs_metadata_filtering_scope.harness_info_id
#   benign_harness_inputs_metadata:
#     repo: benign_harness_inputs_metadatas
#     kind: StreamingInputFilepath
#     key: benign_harness_inputs_metadata_filtering_scope.harness_info_id

#   crashing_harness_inputs_metadata_filtering_scope:
#     repo: crashing_harness_inputs_metadatas
#     kind: null
#   crashing_harness_inputs:
#     repo: crashing_harness_inputs
#     kind: StreamingInputFilepath
#     key: crashing_harness_inputs_metadata_filtering_scope.harness_info_id
#   crashing_harness_inputs_metadata:
#     repo: crashing_harness_inputs_metadatas
#     kind: StreamingInputFilepath
#     key: crashing_harness_inputs_metadata_filtering_scope.harness_info_id


# coverage_trace.benign_harness_inputs/              04-May-2025 15:04       -
# coverage_trace.benign_harness_inputs_metadata/     04-May-2025 15:04       -
# coverage_trace.coverage_build_artifact/            04-May-2025 15:04       -
# coverage_trace.crashing_harness_inputs/            04-May-2025 15:04       -
# coverage_trace.crashing_harness_inputs_metadata/   04-May-2025 15:04       -
# coverage_trace.done/                               04-May-2025 15:04       -
# coverage_trace.functions_index/                    04-May-2025 15:04       -
# coverage_trace.functions_jsons_dir/                04-May-2025 15:04       -
# coverage_trace.harness_info/                       04-May-2025 15:04       -
# coverage_trace.harness_info_id/                    04-May-2025 15:04       -
# coverage_trace.harness_info_meta/                  04-May-2025 15:04       -
# coverage_trace.logs/                               04-May-2025 15:04       -
# coverage_trace.oss_fuzz_project/                   04-May-2025 15:04       -
# coverage_trace.project_id/                         04-May-2025 15:04       -
# coverage_trace.project_metadata/                   04-May-2025 15:04       -
# coverage_trace.project_metadata_path/              04-May-2025 15:04       -
# coverage_trace.success.__footprint.0/   


export HARNESS_INFO_ID=$HARNESS_INFO_ID
export HARNESS_INFO_FILE=$HARNESS_INFO_FILE
export PROJECT_ID=$PROJECT_ID
export BUILD_CONFIGURATION_ID=$BUILD_CONFIGURATION_ID
export PROJECT_NAME=$PROJECT_NAME
export PROJECT_METADATA_PATH=$PROJECT_METADATA_PATH
export OSS_FUZZ_REPO_PATH=$OSS_FUZZ_REPO_PATH
export DEBUG_BUILD_ARTIFACT=$DEBUG_BUILD_ARTIFACT
export COVERAGE_BUILD_ARTIFACT=$COVERAGE_BUILD_ARTIFACT
export DYVA_BUILD_ARTIFACT=$DYVA_BUILD_ARTIFACT
export TARGET_SOURCE_FOLDER=$TARGET_SOURCE_FOLDER
export FUNCTIONS_BY_FILE_INDEX=$FUNCTIONS_BY_FILE_INDEX
export TARGET_METADATA=$TARGET_METADATA
export FUNCTIONS_INDEX=$FUNCTIONS_INDEX
export TARGET_FUNCTIONS_JSONS_DIR=$TARGET_FUNCTIONS_JSONS_DIR
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO
export ANALYSIS_GRAPH_PASSWORD=$ANALYSIS_GRAPH_PASSWORD
export ANALYSIS_GRAPH_BOLT_URL=$ANALYSIS_GRAPH_BOLT_URL


echo $BACKUP_DIR

# Create a fake backup with just the needed directory 
SIMPLE_BACKUP_DIR=$(mktemp -d)

# All the folder that starts with coverage_trace in the BACKUP_DIR
# needs to be copied in the SIMPLE_BACKUP_DIR
for folder in "$BACKUP_DIR"/coverage_trace.*; do
    sudo cp -rL "$folder" "$SIMPLE_BACKUP_DIR" || true
done

# Change again all the forking permissions
sudo chown -R "$(whoami):$(whoami)" "$SIMPLE_BACKUP_DIR"
sudo chmod -R 755 "$SIMPLE_BACKUP_DIR"

echo "CLEANING USELESS FOLDERS"
rm -rf "$SIMPLE_BACKUP_DIR"/coverage_trace.done
rm -rf "$SIMPLE_BACKUP_DIR"/coverage_trace.logs
rm -rf "$SIMPLE_BACKUP_DIR"/coverage_trace.success.INHIBITION.*


echo "================================="
echo "=======Starting Pydatatask======="
echo "================================="

pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name coverageguy-test
pd restore $SIMPLE_BACKUP_DIR --all

pd status

echo "SIMPLE_BACKUP_DIR: $SIMPLE_BACKUP_DIR"
echo "ANALYSIS_GRAPH_BOLT_URL: $ANALYSIS_GRAPH_BOLT_URL"


# ask the user if they are ready to start pdt
if [ "$1" != "--no-prompt" ]; then
    echo "Are you ready to start pdt? (y/n) [default y]"
    read -r answer
    if [ "$answer" != "n" ]; then
        pd --fail-fast --debug-trace --verbose --global-script-env "ARTIPHISHELL_FAIL_EARLY=1" --global-script-env "ANALYSIS_GRAPH_BOLT_URL=$ANALYSIS_GRAPH_BOLT_URL" run 
    fi
fi

