#!/bin/bash

set -x
set -e


LANG="$1"
BACKUP_DIR="$2"
# strip trailing slash
BACKUP_DIR=${BACKUP_DIR%/}
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-dir>"
    exit 1
elif [ ! -d "$BACKUP_DIR" ]; then
    echo "Invalid backup directory: $BACKUP_DIR"
    exit 1
fi
# lang must be c or java
if [ "$LANG" != "c" ] && [ "$LANG" != "java" ] && [ "$LANG" != "kernel" ]; then
    echo "Invalid language: $LANG"
    exit 1
fi

# just to be safe, make sure there are no links in the backup
mv $BACKUP_DIR $BACKUP_DIR.raw &&
cp -lr $BACKUP_DIR.raw $BACKUP_DIR &&
rm -rf $BACKUP_DIR.raw
# move all <backup>/<dir>.__footprint.1 to <backup>/<dir>
find $BACKUP_DIR -name "*.__footprint.1" -exec sh -c 'cp -rf "$1" "${1%.__footprint.1}"' _ {} \; &> /dev/null &&
# rm all <backup>/<dir>.__footprint.*
rm -rf $BACKUP_DIR/*.__footprint.* &> /dev/null &&
# rm all <backup>/<dir>.INHIBITION*
rm -rf $BACKUP_DIR/*.INHIBITION* &> /dev/null

sudo rm -rf /shared/
pushd ../..
    docker build -t aixcc-invariantguy .
popd 

pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name invariant_testing_pipeline_backup

echo "Restoring from backup"
pd restore $BACKUP_DIR --all &> /dev/null || true

pd rm invariant_build __all__ &> /dev/null || true
pd rm invariant_find_${LANG} __all__ &> /dev/null || true

# whitelist only the tasks that you want to run
# IMPORTANT: MAKE SURE THAT TASKS FOR DIFFERENT LANGUAGES ARE NOT OVERWRITING EACH OTHER
pd --fail-fast --debug-trace --verbose -t invariant_build -t invariant_find_${LANG} run &
RUN_PID=$!

function cleanup() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    pkill -f "pydatatask/cli/main.py agent-http" || true
    docker ps -a --filter "ancestor=aixcc-invariantguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-invariantguy-build-*" -q | xargs -r docker rm -f || true
    exit 1
}
trap cleanup SIGINT

wait $RUN_PID

cleanup