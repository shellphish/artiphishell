#!/bin/bash

FIND_ROOT=$1
OUT_DIR=$2

echo "Linking testcases from $FIND_ROOT to $OUT_DIR"

for f in $(find $FIND_ROOT -name 'id:*' | grep -v 'redundant_edges');
do
    FNAME=$(md5sum "$f" | cut -d' ' -f1)
    # set -x
    rm -f "$OUT_DIR/$FNAME"
    cp -n "$f" "$OUT_DIR/$FNAME"
    # set +x
done