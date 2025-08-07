#!/usr/bin/env bash

# THIS SCRIPT IS PROBABLY OUT OF DATE

set -e
set -x

FILENAME_DEFAULT="$(basename "$1")"
FILENAME=${2-$FILENAME_DEFAULT}

if [ -d "$FILENAME" ]; then
    echo "Directory $FILENAME already exists."
else
    git clone "$1" "$FILENAME"
    (
        pushd "$FILENAME" || exit 1
        make cpsrc-prepare
        popd
    )
fi


rm -rf "$FILENAME/.git"
docker run --rm  -it -v "$PWD/$FILENAME:/mnt" -v shellphish-crs_cp-root:/cp_root ubuntu:22.04 sh -c "cp -r /mnt /tmp/repo && mv /tmp/repo/ /cp_root/$FILENAME"
rm -rf "$FILENAME"
