#!/bin/bash



function inspect_corpus() {
    SYNC_DIR=$1

    # loop from i=0 to infinity, continue while $SYNC_DIR/corpus/id:$i:* exists

    i=0
    while true; do
        i_expanded=$(python -c "print('{:06d}'.format($i))")
        FILE=$(/bin/ls $SYNC_DIR/queue/id:$i_expanded*)
        if [ ! -f "$FILE" ]; then
            break
        fi
        clear
        echo "### $FILE"
        xxd "$FILE" | head -n 40
        read
        i=$((i+1))
    done
}

# set -x
inspect_corpus "$1"