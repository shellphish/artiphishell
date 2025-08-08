
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

function prep-source() {
    if [ "$FORCE_GIT_SSH" = "true" ]; then
        sed -i 's|https://github.com/|git@github.com:|' project.yaml
    fi
    make cpsrc-prepare
    if [ "$FULLMODE" = true ]; then
        # Find and remove all .git directories recursively
        find . -type d -name ".git" -exec rm -rf {} +
        touch .full-mode
    fi
}

function target-docker-setup() {
    make docker-pull || make docker-build
}

mkdir -p $TARGET_DIR
rm -rf $FILENAME

while true;
do
    NEED_PULL=true

    if [ -d "$FILENAME" ]; then
        echo "Directory $FILENAME already exists."
        pushd "$FILENAME" || exit 1
        # TODO check if the gitrepo or any soruce was updated...
        prep-source
        target-docker-setup
        popd
        # If we are not in full mode but there is a .full-mode file, we need to pull
        NEED_PULL=false
        if [ ! "$FULLMODE" = true ] && [ -f "$FILENAME/.full-mode" ]; then
            NEED_PULL=true
        fi
    fi
    if [ "$NEED_PULL" = true ]; then
        rm -rf $FILENAME
        git clone "$1" "$FILENAME"
        (
            pushd "$FILENAME" || exit 1
            prep-source
            target-docker-setup

            sudo rm -rf "$FILENAME/.git"
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
