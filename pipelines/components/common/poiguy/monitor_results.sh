#!/bin/bash

while true; do
    ln -s "$IN_DIR"/* "$OUT_LOCK_DIR"/
    rsync -av "$IN_DIR"/ "$OUT_DIR"/
    FILES=$(find "$IN_DIR" -type f)
    for f in $FILES;
    do
        rel_path=$(realpath --relative-to="$IN_DIR" $f)
        echo "filename: $rel_path" > "$OUT_META_DIR"/$(basename $f)
    done
    rm "$OUT_LOCK_DIR"/*
    sleep 10
done
