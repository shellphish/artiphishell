#!/bin/bash
set -e
set -x

# INPUTS
WORK_BENIGN_HARNESS_INPUTS_MAIN_DIR=/work/benign_harness_inputs_main_dir
WORK_BENIGN_HARNESS_INPUTS_LOCK_DIR=/work/benign_harness_inputs_lock_dir
WORK_BENIGN_HARNESS_INPUTS_METADATA_MAIN_DIR=/work/benign_harness_inputs_metadata_main_dir
WORK_BENIGN_HARNESS_INPUTS_METADATA_LOCK_DIR=/work/benign_harness_inputs_metadata_lock_dir
WORK_CRASHING_HARNESS_INPUTS_MAIN_DIR=/work/crashing_harness_inputs_main_dir
WORK_CRASHING_HARNESS_INPUTS_LOCK_DIR=/work/crashing_harness_inputs_lock_dir
WORK_CRASHING_HARNESS_INPUTS_METADATA_MAIN_DIR=/work/crashing_harness_inputs_metadata_main_dir
WORK_CRASHING_HARNESS_INPUTS_METADATA_LOCK_DIR=/work/crashing_harness_inputs_metadata_lock_dir

WORK_TARGET_METADATUM=/work/target_metadatum
cp $TARGET_METADATUM_PATH $TARGET_DIR/work/target_metadatum

mkdir -p $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_MAIN_DIR
mkdir -p $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_LOCK_DIR
mkdir -p $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_METADATA_MAIN_DIR
mkdir -p $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_METADATA_LOCK_DIR
mkdir -p $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_MAIN_DIR
mkdir -p $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_LOCK_DIR
mkdir -p $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_METADATA_MAIN_DIR
mkdir -p $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_METADATA_LOCK_DIR
/shellphish/coverageguy/inotify_sync.sh $BENIGN_HARNESS_INPUTS_MAIN_DIR $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_MAIN_DIR &
/shellphish/coverageguy/inotify_sync.sh $BENIGN_HARNESS_INPUTS_LOCK_DIR $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_LOCK_DIR &
/shellphish/coverageguy/inotify_sync.sh $BENIGN_HARNESS_INPUTS_METADATA_MAIN_DIR $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_METADATA_MAIN_DIR &
/shellphish/coverageguy/inotify_sync.sh $BENIGN_HARNESS_INPUTS_METADATA_LOCK_DIR $TARGET_DIR/$WORK_BENIGN_HARNESS_INPUTS_METADATA_LOCK_DIR &
/shellphish/coverageguy/inotify_sync.sh $CRASHING_HARNESS_INPUTS_MAIN_DIR $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_MAIN_DIR &
/shellphish/coverageguy/inotify_sync.sh $CRASHING_HARNESS_INPUTS_LOCK_DIR $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_LOCK_DIR &
/shellphish/coverageguy/inotify_sync.sh $CRASHING_HARNESS_INPUTS_METADATA_MAIN_DIR $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_METADATA_MAIN_DIR &
/shellphish/coverageguy/inotify_sync.sh $CRASHING_HARNESS_INPUTS_METADATA_LOCK_DIR $TARGET_DIR/$WORK_CRASHING_HARNESS_INPUTS_METADATA_LOCK_DIR &

# OUTPUTS
WORK_BENIGN_COVERAGES=/work/benign_coverages
WORK_BENIGN_COVERAGES_FULL_REPORT=/work/benign_coverages_full_report
WORK_CRASHING_COVERAGES=/work/crashing_coverages
WORK_CRASHING_COVERAGES_FULL_REPORT=/work/crashing_coverages_full_report
mkdir -p $TARGET_DIR/$WORK_BENIGN_COVERAGES
mkdir -p $TARGET_DIR/$WORK_BENIGN_COVERAGES_FULL_REPORT
mkdir -p $TARGET_DIR/$WORK_CRASHING_COVERAGES
mkdir -p $TARGET_DIR/$WORK_CRASHING_COVERAGES_FULL_REPORT
/shellphish/coverageguy/inotify_sync.sh $TARGET_DIR/$WORK_BENIGN_COVERAGES $BENIGN_COVERAGES &
/shellphish/coverageguy/inotify_sync.sh $TARGET_DIR/$WORK_BENIGN_COVERAGES_FULL_REPORT $BENIGN_COVERAGES_FULL_REPORT &
/shellphish/coverageguy/inotify_sync.sh $TARGET_DIR/$WORK_CRASHING_COVERAGES $CRASHING_COVERAGES &
/shellphish/coverageguy/inotify_sync.sh $TARGET_DIR/$WORK_CRASHING_COVERAGES_FULL_REPORT $CRASHING_COVERAGES_FULL_REPORT &

# create monitoring configuration
cat <<EOF > $TARGET_DIR/work/monitor_config.yaml
benign_harness_inputs_main_dir: $WORK_BENIGN_HARNESS_INPUTS_MAIN_DIR
benign_harness_inputs_lock_dir: $WORK_BENIGN_HARNESS_INPUTS_LOCK_DIR
benign_harness_inputs_metadata_main_dir: $WORK_BENIGN_HARNESS_INPUTS_METADATA_MAIN_DIR
benign_harness_inputs_metadata_lock_dir: $WORK_BENIGN_HARNESS_INPUTS_METADATA_LOCK_DIR
crashing_harness_inputs_main_dir: $WORK_CRASHING_HARNESS_INPUTS_MAIN_DIR
crashing_harness_inputs_lock_dir: $WORK_CRASHING_HARNESS_INPUTS_LOCK_DIR
crashing_harness_inputs_metadata_main_dir: $WORK_CRASHING_HARNESS_INPUTS_METADATA_MAIN_DIR
crashing_harness_inputs_metadata_lock_dir: $WORK_CRASHING_HARNESS_INPUTS_METADATA_LOCK_DIR
benign_coverages: $WORK_BENIGN_COVERAGES
benign_coverages_full_report: $WORK_BENIGN_COVERAGES_FULL_REPORT
crashing_coverages: $WORK_CRASHING_COVERAGES
crashing_coverages_full_report: $WORK_CRASHING_COVERAGES_FULL_REPORT
target_metadatum_path: $WORK_TARGET_METADATUM
EOF
cat $TARGET_DIR/work/monitor_config.yaml

echo ">>> Setting Jazzer garbage collection <<<"
sed -i '/JAVA_OPTS/d' "$TARGET_DIR/.env.docker"
echo 'JAVA_OPTS=-Xmx4096m' >> "$TARGET_DIR/.env.docker"

echo ">>> Extracting the classes in scope <<<"
# Extract the classes in scope and put them in /work

# IMPORTANT: THIS MUST INVOKE THE BUILD-TIME HARNESS
sed -i '/THE_FUCKING_SCRIPT/d' $TARGET_DIR/.env.docker
echo "THE_FUCKING_SCRIPT=/shellphish/coverageguy/jar_extractor.py" >> $TARGET_DIR/.env.docker
sed -i '/CP_HARNESS_NAME/d' $TARGET_DIR/.env.docker
echo "CP_HARNESS_NAME=$CP_HARNESS_NAME" >> $TARGET_DIR/.env.docker
sed -i '/CP_HARNESS_BINARY_PATH/d' $TARGET_DIR/.env.docker
echo "CP_HARNESS_BINARY_PATH=$CP_HARNESS_BINARY_PATH" >> $TARGET_DIR/.env.docker

# IMPORTANT: /work/pov must be exactly "known-pov-contents"
echo known-pov-contents > $TARGET_DIR/work/pov
$TARGET_DIR/run.sh run_pov $TARGET_DIR/work/pov $CP_HARNESS_NAME

echo ">>> Starting Java Monitor <<<"

# IMPORTANT: THIS MUST INVOKE THE TRACE-TIME HARNESS
sed -i '/THE_FUCKING_SCRIPT/d' $TARGET_DIR/.env.docker
echo "THE_FUCKING_SCRIPT=/shellphish/coverageguy/java_in_docker_monitor.py" >> $TARGET_DIR/.env.docker

# IMPORTANT: /work/pov must be exactly "known-pov-contents"
echo known-pov-contents > $TARGET_DIR/work/pov
$TARGET_DIR/run.sh run_pov $TARGET_DIR/work/pov $CP_HARNESS_NAME