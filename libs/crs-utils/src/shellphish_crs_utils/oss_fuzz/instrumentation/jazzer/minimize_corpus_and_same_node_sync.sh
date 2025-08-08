#! /bin/bash

set -u
set -e

RSYNC_SLEEP=200
MINIMIZE_TIMEOUT=1000

# Fuzzing and seeds dir for Jazzer for each harness
export ARTIPHISHELL_FUZZER_BASEDIR="/shared/jazzer/fuzz"
export JAZZER_INSTANCE_UNIQUE_NAME=${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/
export JAZZER_INSTANCE_PATH_FOR_EACH_HARNESS="$ARTIPHISHELL_FUZZER_BASEDIR/$JAZZER_INSTANCE_UNIQUE_NAME"

# jazzer replicas
export ARTIPHISHELL_FUZZER_INSTANCE_NAME_REPLICA_FULL="${ARTIPHISHELL_SHELLPHISH_PROJECT_ID}-${JOB_ID}-${REPLICA_ID}"
export ARTIPHISHELL_FUZZER_INSTANCE_REPLICA_DIR=$JAZZER_INSTANCE_PATH_FOR_EACH_HARNESS/$ARTIPHISHELL_FUZZER_INSTANCE_NAME_REPLICA_FULL
mkdir -p $ARTIPHISHELL_FUZZER_INSTANCE_REPLICA_DIR

# FUZZER SYNC DIR to get all mimimized seeds during fuzzing
export ARTIPHISHELL_FUZZER_SYNC_PATH="/shared/fuzzer_sync/$JAZZER_INSTANCE_UNIQUE_NAME"

MERGE_CONTROL_FILE="/shared/fuzzer_sync/$JAZZER_INSTANCE_UNIQUE_NAME/merge_control_file"

# delete symlinked version of jazzer and run original jazzer
unlink /out/jazzer_driver
cp /out/jazzer_driver.orig /out/jazzer_driver
# FIXME: rm this after adding merge to jazzer wrapper - maybe not!
cp /out/jazzer_agent_deploy.jar.orig /out/jazzer_agent_deploy.jar

###
# Background rsync task
###

while true; do 

    mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/queue/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/losan_crashes/"
    mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-minimized/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-minimized/queue/"

    echo "=========================================="
    echo " EACH FUZZER INSTANCE SYNC ON SAME NODE"
    echo "=========================================="
    
    # Delete this print after pipeline is stable!
    ls -l $JAZZER_INSTANCE_PATH_FOR_EACH_HARNESS/

    # merge_sources=() # collect fuzzing instance names for merge task later
    for FUZZER_INSTANCE in "$JAZZER_INSTANCE_PATH_FOR_EACH_HARNESS"/*; do
        echo "Trying instance: $FUZZER_INSTANCE"
        if [ -d "$FUZZER_INSTANCE" ]; then
            echo "Processing instance: $(basename "$FUZZER_INSTANCE")"
            if [ -d "$FUZZER_INSTANCE/crashes" ]; then
                rsync -ra --include='crash*' --include='timeout*' --include='oom*' --exclude='*' "$FUZZER_INSTANCE/crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/crashes/" || true
            fi

            # losan crashes. we exclude timeout and ooms
            if [ -d "$FUZZER_INSTANCE/losan_crashes" ]; then
                rsync -ra --include='crash*' --exclude='*' "$FUZZER_INSTANCE/losan_crashes/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/losan_crashes/" || true
            fi

            if [ -d "$FUZZER_INSTANCE/queue" ]; then
                rsync -ra "$FUZZER_INSTANCE/queue/" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/queue/" || true
            fi

            # TODO: Delete prints after pipeline is stable!
            echo "Seeds in : $FUZZER_INSTANCE $(ls "$FUZZER_INSTANCE/queue/" | wc -l)"
            echo "Crashes in : $FUZZER_INSTANCE $(ls "$FUZZER_INSTANCE/crashes/" | wc -l)"
            echo "Losan Crashes in : $FUZZER_INSTANCE $(ls "$FUZZER_INSTANCE/losan_crashes/" | wc -l)"
        fi
    done
    
    echo "Seeds after rsync round: $ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/queue/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/queue/" | wc -l)"
    echo "Crashes after rsync round : $ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/crashes/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/crashes/" | wc -l)"
    echo "Losan crashes after rsync round : $ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/losan_crashes/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/losan_crashes/" | wc -l)"
    sleep $RSYNC_SLEEP
    
done &  


### 
# Merge task
###

while true; do 
    echo "=========================================="
    echo " MERGE TASK"
    echo "=========================================="
    start_time=$(date +%s)
    # Start the merge task in the background with the control file.
    $ARTIPHISHELL_HARNESS_NAME -merge=1 -verbosity=2 -merge_control_file="$MERGE_CONTROL_FILE" "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-minimized/queue/"  "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-all/queue/" & MERGE_PID=$!


    echo "Merge pid: $MERGE_PID"
    echo "Sleeping for $MINIMIZE_TIMEOUT secs ..."
    sleep $MINIMIZE_TIMEOUT


    # If the merge is still running, send SIGUSR1 to gracefully pause it.
    if kill -0 $MERGE_PID 2>/dev/null; then
        echo "Merge still running. Sending SIGUSR1 to pause merge."

        # Collect child PIDs before sending signal
        CHILD_PIDS=$(pgrep -P $MERGE_PID 2>/dev/null || true)
        echo "Child processes of $MERGE_PID: $CHILD_PIDS"

        # DEBUG: Show what would be killed in each child tree
        if [ -n "$CHILD_PIDS" ]; then
            echo "=== DEBUG: Analyzing process trees ==="
            for child in $CHILD_PIDS; do
                echo "=== Child $child ===" 
                pstree -p $child
                # echo "=== details ====="
                # pstree -p $child 2>/dev/null | grep -o '([0-9]*)' | grep -o '[0-9]*' | tac | sed 's/^/Would kill PID: /'
            done
            echo "=== End DEBUG ==="
        fi
    
        # Send graceful signal to main process
        kill -SIGUSR1 $MERGE_PID
        # Wait for the merge process to exit gracefully.
        wait $MERGE_PID 2>/dev/null || true

        # Kill entire process trees for each child
        for child in $CHILD_PIDS; do
            if kill -0 $child 2>/dev/null; then
                echo "Killing tree for child: $child"
                pstree -p $child 2>/dev/null | grep -o '([0-9]*)' | grep -o '[0-9]*' | tac | xargs -r kill -KILL 2>/dev/null || true
            fi
        done
    fi

    # Final cleanup - kill any survivors by name
    echo "Final cleanup of remaining processes..."
    for process_pattern in "target_class" "jvm"; do
        REMAINING=$(pgrep -f "$process_pattern" | wc -l)
        if [ "$REMAINING" -gt 0 ]; then
            echo "Killing $REMAINING remaining $process_pattern processes..."
            pgrep -f "$process_pattern" | xargs -r kill -KILL 2>/dev/null || true
            sleep 1
            SURVIVORS=$(pgrep -f "$process_pattern" | wc -l)
            [ "$SURVIVORS" -eq 0 ] && echo "All $process_pattern processes killed" || echo "ERROR: $SURVIVORS $process_pattern processes survived"
        else
            echo "No $process_pattern processes found!"
        fi
    done

    end_time=$(date +%s)
    echo "Merge completed! Execution time: $((end_time - start_time)) seconds"
    echo "Seeds after merge: $ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-minimized/queue/ $(ls "$ARTIPHISHELL_FUZZER_SYNC_PATH/jazzer-minimized/queue/" | wc -l)"
done
