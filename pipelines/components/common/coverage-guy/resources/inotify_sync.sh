#!/bin/bash

set -x

INPUT_DIR=$1
OUTPUT_DIR=$2


# cp one file at the time on close_write
while true; do
    inotifywait -m -e close_write "$INPUT_DIR" -e move --format "%w%f" | while read file; do
        # echo Syncing file $file to $OUTPUT_DIR
        if [ -e "$file" ]; then
            TMPFILE=$(mktemp)
            BASENAME=$(basename "$file")
            cp -af "$file" "$TMPFILE" && mv "$TMPFILE" "$OUTPUT_DIR/$BASENAME" || true
        fi
    done || true
    # maybe sync lost events
done &
PID1=$!

# delete file on delete
while true; do
    inotifywait -m -e delete "$INPUT_DIR" --format "%w%f" | while read file; do
        # echo Deleting file $file
        BASENAME=$(basename "$file")
        rm -f "$OUTPUT_DIR/$BASENAME"
    done || true
    # maybe sync lost events
done &
PID2=$!

# rsync the whole directory at start: sleep 5 seconds, then rsync all files older than 5 seconds
# IMPORTANT: this must run after the watchers start
REFERENCE_FILE=$(mktemp)
sleep 5
find "$INPUT_DIR" \! -newer $REFERENCE_FILE -type f | while read file; do
    BASENAME=$(basename "$file")
    if [ ! -e "$OUTPUT_DIR/$BASENAME" ]; then
        TMPFILE=$(mktemp)
        cp -a "$file" "$TMPFILE" && mv "$TMPFILE" "$OUTPUT_DIR/$BASENAME" || true
    fi
done

# trap on exit to kill the processes
trap "kill $PID1 $PID2" EXIT

# wait for both processes to finish
wait $PID1
wait $PID2