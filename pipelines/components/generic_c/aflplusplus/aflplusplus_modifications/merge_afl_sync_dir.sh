#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring
set -u # fail and exit if any variable is used before being set

CP_NAME="$1"
SYNCDIR="$2"
SEEDS_DIR="$3"
CRASHES_DIR="$4"

set +x
function update_files() {
    local in_dir=$1
    local out_dir=$2
    local files_modified_last_10min=$(find $in_dir -type f -mmin -10 -name 'id:*' | grep -v '.state')
    for file in $files_modified_last_10min; do
        file_sha256=$(sha256sum $file | cut -d ' ' -f 1)
        if [ ! -f "$out_dir/$file_sha256" ]; then
            echo "Copying new $file to $out_dir/$file_sha256"
            cp $file $out_dir/$file_sha256 || true
        fi
    done
}
while true; do
    # rsync all files that match 'id:*'
    echo "Syncing files for $SYNCDIR to seeds_dir=$SEEDS_DIR and crashes_dir=$CRASHES_DIR"

    update_files $SYNCDIR/queue $SEEDS_DIR
    update_files $SYNCDIR/crashes $CRASHES_DIR
    sleep 20
done
