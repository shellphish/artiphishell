#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INGESTED_DIR=$SCRIPT_DIR/ingested
rm -rf $INGESTED_DIR
mkdir $INGESTED_DIR
while true; do
    (find $SCRIPT_DIR/targets -name '*.ready' -mindepth 2 -maxdepth 2) | while read -r cp_filename; do
        cp_filename="$(basename ${cp_filename%.ready})"
#        echo $cp_filename
        if ! [ -e "$INGESTED_DIR/$cp_filename.yaml" ]; then
            LAST_ID="$(pd ls pipeline_inputs.target_with_sources | sort -n | tail -n1)"
            ident=$((LAST_ID + 1))
            (cd $SCRIPT_DIR/targets/$cp_filename && tar --owner=0 --group=0 -czf "$INGESTED_DIR/$cp_filename.tar.gz" .)
            (
                echo "id: '$ident'"
                echo "orig_filename: $cp_filename"
            ) >"$INGESTED_DIR/$cp_filename.yaml"
            pd inject pipeline_inputs.target_with_sources "$ident" <"$INGESTED_DIR/$cp_filename.tar.gz"
        fi
    done
    sleep 5
done