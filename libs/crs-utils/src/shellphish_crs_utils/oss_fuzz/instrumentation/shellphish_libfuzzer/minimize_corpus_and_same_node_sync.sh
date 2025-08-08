#! /bin/bash

set -u
set -e

RSYNC_SLEEP=100
MINIMIZE_TIMEOUT=800

# Fuzzing and seeds dir for libFuzzer for each harness
export ARTIPHISHELL_FUZZER_BASEDIR="/shared/libfuzzer/fuzz"
export LIBFUZZER_INSTANCE_UNIQUE_NAME=${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/
export LIBFUZZER_INSTANCE_PATH_FOR_EACH_HARNESS="$ARTIPHISHELL_FUZZER_BASEDIR/$LIBFUZZER_INSTANCE_UNIQUE_NAME"

# libfuzzer replicas
export ARTIPHISHELL_FUZZER_INSTANCE_NAME_REPLICA_FULL="${ARTIPHISHELL_SHELLPHISH_PROJECT_ID}-${JOB_ID}-${REPLICA_ID}"
export ARTIPHISHELL_FUZZER_INSTANCE_REPLICA_DIR=$LIBFUZZER_INSTANCE_PATH_FOR_EACH_HARNESS/$ARTIPHISHELL_FUZZER_INSTANCE_NAME_REPLICA_FULL
mkdir -p $ARTIPHISHELL_FUZZER_INSTANCE_REPLICA_DIR

# FUZZER SYNC DIR to get all mimimized seeds during fuzzing
export ARTIPHISHELL_FUZZER_SYNC_PATH="/shared/fuzzer_sync/$LIBFUZZER_INSTANCE_UNIQUE_NAME"

MERGE_CONTROL_FILE="/shared/fuzzer_sync/$LIBFUZZER_INSTANCE_UNIQUE_NAME/merge_control_file"

# delete symlinked version of jazzer and run original jazzer
# unlink /out/jazzer_driver
# cp /out/jazzer_driver.orig /out/jazzer_driver
# # FIXME: rm this after adding merge to jazzer wrapper - maybe not!
# cp /out/jazzer_agent_deploy.jar.orig /out/jazzer_agent_deploy.jar

unlink "/out/$ARTIPHISHELL_HARNESS_NAME"
mv "/out/$ARTIPHISHELL_HARNESS_NAME.instrumented" "/out/$ARTIPHISHELL_HARNESS_NAME"
export ARTIPHISHELL_HARNESS_PATH="/out/$ARTIPHISHELL_HARNESS_NAME"

###
# Background rsync task
###

while true; do 

    mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/"
    mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/"

    echo "=========================================="
    echo " EACH FUZZER INSTANCE SYNC ON SAME NODE"
    echo "=========================================="
    
    # Delete this print after pipeline is stable!
    ls -l $LIBFUZZER_INSTANCE_PATH_FOR_EACH_HARNESS/

    # merge_sources=() # collect fuzzing instance names for merge task later
    for FUZZER_INSTANCE in "$LIBFUZZER_INSTANCE_PATH_FOR_EACH_HARNESS"/*; do
        echo "Trying instance: $FUZZER_INSTANCE"
        if [ -d "$FUZZER_INSTANCE" ]; then
            echo "Processing instance: $(basename "$FUZZER_INSTANCE")"
            if [ -d "$FUZZER_INSTANCE/crashes" ]; then
                rsync -ra --include='crash*' --include='timeout*' --include='oom*' --exclude='*' "$FUZZER_INSTANCE/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" || true
            fi

            if [ -d "$FUZZER_INSTANCE/queue" ]; then
                rsync -ra "$FUZZER_INSTANCE/queue/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/" || true
                # merge_sources+=("$FUZZER_INSTANCE/queue")
            fi

            # TODO: Delete prints after pipeline is stable!
            echo "Seeds in : $FUZZER_INSTANCE $(ls "$FUZZER_INSTANCE/queue/" | wc -l)"
            echo "Crashes in : $FUZZER_INSTANCE $(ls "$FUZZER_INSTANCE/crashes/" | wc -l)"
        fi
    done
    
    echo "Seeds after rsync round: $ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/" | wc -l)"
    echo "Crashes after rsync round : $ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/" | wc -l)"
    sleep $RSYNC_SLEEP
    
done &  


### 
# Merge task
###

# TODO: maybe this is fine for libfuzzer?
while true; do 
    echo "=========================================="
    echo " MERGE TASK"
    echo "=========================================="
    # Start the merge task in the background with the control file.
    $ARTIPHISHELL_HARNESS_PATH -merge=1 -merge_control_file="$MERGE_CONTROL_FILE" \
        "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/"  "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/queue/" &
    MERGE_PID=$!

    echo "Sleeping for 1000 secs ..."
    sleep $MINIMIZE_TIMEOUT

    # If the merge is still running, send SIGUSR1 to gracefully pause it.
    if kill -0 $MERGE_PID 2>/dev/null; then
        echo "Merge still running. Sending SIGUSR1 to pause merge."
        kill -SIGUSR1 $MERGE_PID
        # Wait for the merge process to exit gracefully.
        wait $MERGE_PID 2>/dev/null || true
    fi

    echo "Seeds after merge: $ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/" | wc -l)"
done
