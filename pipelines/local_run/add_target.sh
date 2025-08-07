#!/usr/bin/env bash

set -e
set -x

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <git-url>"
    exit 1
fi
FILENAME_DEFAULT="$(basename "$1")"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TARGET_DIR=$SCRIPT_DIR/targets
FILENAME=$TARGET_DIR/$FILENAME_DEFAULT
INGESTED_DIR=$SCRIPT_DIR/ingested
mkdir -p $INGESTED_DIR

function target-docker-setup() {
    make docker-pull || make docker-build
}


while true;
do
    mkdir -p $TARGET_DIR
    rm -rf $FILENAME
    if [ -d "$FILENAME" ]; then
        echo "Directory $FILENAME already exists."
        # do the docker stuff just in case (mainly for CI)
        pushd "$FILENAME"
        target-docker-setup
        popd
    else
        git clone "$1" "$FILENAME"
        (
            pushd "$FILENAME" || exit 1
            make cpsrc-prepare
            target-docker-setup
            rm -rf "$FILENAME/.git"
            touch .ready
            popd
        )
    fi

    OUTPUT=$INGESTED_DIR/$FILENAME_DEFAULT.tar.gz
    (cd $FILENAME && tar --owner=0 --group=0 -czf "$OUTPUT" .)
    tar tf $OUTPUT 
    if [ $? -eq 0 ]; then
        break
    fi
done