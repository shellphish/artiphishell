#!/bin/bash

set -x
set -e

BACKUP_DIR=$1

function cleanup() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-coverageguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-coverageguy-build-*" -q | xargs -r docker rm -f || true
    exit 1
}
trap cleanup SIGINT

# check if parameter has been given 
if [ -z "$BACKUP_DIR" ]; then
    # If no directory is given, print usage and exit
    echo "Running without backup directory"
    sleep 10

    docker login ghcr.io -u player-c3f09220 -p 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
    pushd ../../../../../local_run/
    ./rebuild_local.sh
    popd
    pushd ../../../../../components/common/base/
    docker build -t aixcc-component-base -f Dockerfile.component-base .
    popd
    pushd ../../
    docker build -t aixcc-grammar-guy .
    popd

    if [ ! -d targets-semis-aixcc-sc-challenge-004-nginx-cp ]; then
        git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp
        (
            pushd targets-semis-aixcc-sc-challenge-004-nginx-cp
            set -x
            make cpsrc-prepare
            popd
        )
    fi
    if [ ! -f targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz ]; then
        tar czf targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz -C targets-semis-aixcc-sc-challenge-004-nginx-cp .
    fi

    pdl --unlock || rm -rf pipeline.lock
    pdl --name grammar_guy_feature_test_nginx_cp
    pd inject analyze_target.target_with_sources 1 < targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz
    pd --verbose run

    exit 0
else
    echo "Running with backup directory: $BACKUP_DIR"    
    # strip trailing slash
    BACKUP_DIR=${BACKUP_DIR%/}
    if [ ! -d $BACKUP_DIR ]; then
        echo "Invalid backup directory: $BACKUP_DIR"
        exit 1
    fi
    
    # just to be safe, make sure there are no links in the backup
    mv $BACKUP_DIR $BACKUP_DIR.raw &&
    cp -lr $BACKUP_DIR.raw $BACKUP_DIR &&
    rm -rf $BACKUP_DIR.raw
    # just to be safe, move all <backup>/<dir>.__footprint.1 to <backup>/<dir>
    find $BACKUP_DIR -name "*.__footprint.1" -exec sh -c 'cp -rf "$1" "${1%.__footprint.1}"' _ {} \; &> /dev/null &&
    # then rm all <backup>/<dir>.__footprint.*
    rm -rf $BACKUP_DIR/*.__footprint.* &> /dev/null

    # sudo rm -rf /shared/
    pushd ../../
    docker build -t aixcc-grammar-guy .
    popd

    pdl --unlock || rm -rf pipeline.lock
    pdl --ignore-required --name gg-testing-jenkins

    echo "Restoring from backup"
    pd restore $BACKUP_DIR --all &> /dev/null || true
    pd rm grammar_guy_fuzz __all__
    pd --verbose run

fi

# cleanup