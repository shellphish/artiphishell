#!/bin/bash



function inspect_corpus() {
    SYNC_DIR=$1

    # loop from i=0 to infinity, continue while $SYNC_DIR/corpus/id:$i:* exists

    i=0
    while true; do
        FILE=$(/bin/ls $SYNC_DIR/corpus/id:$i:*)
        if [ ! -f "$FILE" ]; then
            break
        fi
        clear
        echo "### $FILE"
        xxd "$FILE" | head -n 40
        sleep .1
        i=$((i+1))
    done
}

# set -x
inspect_corpus "$1"