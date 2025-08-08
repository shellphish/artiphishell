
#!/bin/bash

# TEST PARAMETERS
SEEDS_HIJACKING=no
SEEDS_HIJACKING_DIR_BENIGN=/shared/covguy-seeds_hijacking_benign
SEEDS_HIJACKING_DIR_MALICIOUS=/shared/covguy-seeds_hijacking_malicious


BACKUP_DIR_NAME="backup-nginx-14422031803-latest"
PROJECT_ID="f94dc7fd0f2a4324b5fc92e80fed434d"
COVBUILD_ARTIFACTS_DIR="/aixcc-backups/$BACKUP_DIR_NAME/coverage_build_c.coverage_build_artifacts"
HARNESS_ID="c28bafb1f300869069a6ca00225df915"
TARGET_DIR="$COVBUILD_ARTIFACTS_DIR/$PROJECT_ID"

# Make a full copy of the target_dir in /shared (including hidden files)
TARGET_DIR_NEW_FOLDER=/shared/covguy-coverage_build_artifacts
rm -rf $TARGET_DIR_NEW_FOLDER
cp -r $TARGET_DIR $TARGET_DIR_NEW_FOLDER


export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:helloworldpdt@172.17.0.4:7687"

# if the SEEDS_HIJACKING boolean is yes, then we are using that folder as queue
if [ "$SEEDS_HIJACKING" == "yes" ]; then
    echo "Executing test_monitor.py with SEEDS_HIJACKING"
    python test_monitor.py --harness_info_id /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.harness_info_id/$HARNESS_ID.yaml \
                        --harness_info /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.harness_info/$HARNESS_ID.yaml \
                        --target_dir $TARGET_DIR_NEW_FOLDER \
                        --project_metadata /aixcc-backups/$BACKUP_DIR_NAME/analyze_target.metadata_path/$PROJECT_ID.yaml \
                        --project_id $PROJECT_ID \
                        --function_index /aixcc-backups/$BACKUP_DIR_NAME/generate_full_function_index.target_functions_index/$PROJECT_ID \
                        --function_index_json_dir /aixcc-backups/$BACKUP_DIR_NAME/generate_full_function_index.target_functions_jsons_dir/$PROJECT_ID \
                        --crashing_inputs_dir $SEEDS_HIJACKING_DIR_MALICIOUS \
                        --benign_inputs_dir $SEEDS_HIJACKING_DIR_BENIGN
else
    echo "Executing with original benign and crashing seeds"
    python test_monitor.py --harness_info_id /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.harness_info_id/$HARNESS_ID.yaml \
                        --harness_info /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.harness_info/$HARNESS_ID.yaml \
                        --target_dir $TARGET_DIR_NEW_FOLDER \
                        --project_metadata /aixcc-backups/$BACKUP_DIR_NAME/analyze_target.metadata_path/$PROJECT_ID.yaml \
                        --project_id $PROJECT_ID \
                        --function_index /aixcc-backups/$BACKUP_DIR_NAME/generate_full_function_index.target_functions_index/$PROJECT_ID \
                        --function_index_json_dir /aixcc-backups/$BACKUP_DIR_NAME/generate_full_function_index.target_functions_jsons_dir/$PROJECT_ID \
                        --crashing_inputs_dir /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.crashing_harness_inputs/ \
                        --benign_inputs_dir /aixcc-backups/$BACKUP_DIR_NAME/coverage_trace.benign_harness_inputs/
fi