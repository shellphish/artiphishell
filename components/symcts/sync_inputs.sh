#!/bin/bash

set -e # fail and exit on any command erroring

set -x
OUT_DIR=$1
SYNCDIR=$2
SEEDS_DIR=$3
CRASHES_DIR=$4
MERGED_DIR=$OUT_DIR/merged/

sync_inputs_over_time() {
    DIR_TO_WATCH=$1
    DIR_TO_DUMP=$2
    # inotifywait watch for new files in the sync dir, dump them to the output dir with the filename being the sha256sum
    inotifywait -m -e create --format '%w%f' $DIR_TO_WATCH | while read FILE; do
        # if the file does not start with id: then it is not a file we want to sync
        if [[ ! "$FILE" == id:* ]]; then
            continue
        fi
        echo "New file detected: $FILE"
        sha256sum "$FILE" | awk '{print $1}' | xargs -I {} mv "$FILE" $DIR_TO_DUMP/{}
    done
}

watch_merged() {
python3 /sync_inputs_inotify.py $MERGED_DIR/ $SEEDS_DIR $CRASHES_DIR || \
python3 /sync_inputs_polling.py $MERGED_DIR/ $SEEDS_DIR $CRASHES_DIR
}


mkdir -p $MERGED_DIR/merged_inputs/{queue,crashes}
# sync_inputs_over_time $MERGED_DIR/queue $SEEDS_DIR &
# sync_inputs_over_time $MERGED_DIR/crashes $CRASHES_DIR &
watch_merged &

while true; do
    for fuzzer_dir in $SYNCDIR/*/; do
        echo "Syncing files for fuzzer $fuzzer_dir to seeds_dir=$MERGED_DIR/merged_inputs/queue and crashes_dir=$MERGED_DIR/merged_inputs/crashes"
        rsync -raz --include='id:*' --exclude='*' $fuzzer_dir/queue/ $MERGED_DIR/merged_inputs/queue || true
        rsync -raz --include='id:*' --exclude='*' $fuzzer_dir/crashes/ $MERGED_DIR/merged_inputs/crashes || true
    done
    sleep 60
done
# wait
