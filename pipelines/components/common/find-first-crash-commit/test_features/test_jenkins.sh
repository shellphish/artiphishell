#!/usr/bin/bash

set -e
set -x

add_target_files () {
    NAME="$1"
    TAR_FILE="$NAME.tar.gz"
    if [ ! -f "$TAR_FILE" ]; then
        git clone https://github.com/shellphish-support-syndicate/"$NAME".git
        pushd "$NAME"
        make cpsrc-prepare
        ls
        tar -czvf "../$TAR_FILE" .
        popd
        rm -rf "./$NAME"
    fi

}

get_target_file_name () {
    NAME=$1
    OUT=$(grep "^${NAME}" $TARGET_NAME_MAP)
    FULL_NAME=$(echo "$OUT" | cut -d',' -f2)
    echo "$FULL_NAME"
}


get_all_targets () {
    DELIM="|"
    if [ $# -ge 1 ]; then
        DELIM="$1"
    fi
    OUT=$(awk -v delim="$DELIM" -F',' 'BEGIN {ORS=delim} {print $1}' $TARGET_NAME_MAP)
    echo "${OUT%$DELIM}"
}

usage () {
    echo "Usage: $0 [$(get_all_targets)]"
    exit 1
}

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
TARGET_NAME_MAP="$CUR_DIR/targets.csv"

TARGET=""
if [ $# -ge 1 ]; then
    if [ "$1" == "-h" ]; then
        usage
    fi
    TARGET=$(get_target_file_name "$1")
    if [ -z "$TARGET" ]; then
        echo "Target $1 not in [$(get_all_targets ',')]"
        usage
    fi
else
    TARGET="aixcc-sc-challenge-002-jenkins-cp"
fi

pushd $PARENT
docker build -t aixcc-find-first-crash-commit .
popd

RESOURCE_DIR=$CUR_DIR/resources
pushd $RESOURCE_DIR

if [ ! -f aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-cp/
    pushd aixcc-sc-challenge-002-jenkins-cp
    sed -i 's/git@github.com:aixcc-sc\//http:\/\/github.com\/shellphish-support-syndicate\/aixcc-sc-/g' project.yaml
    sed -i 's/env bash/env bash\nset +e\nset -x/g' ./run.sh

    make cpsrc-prepare
    tar -cvzf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    popd
    rm -rf ./aixcc-sc-challenge-002-jenkins-cp
fi

if [ ! -f seed ]; then
    echo "AAAADQAAAAF4LWV2aWwtYmFja2Rvb3IAYnJlYWtpbiB0aGUgbGF3AGphenpl" | base64 -d > $RESOURCE_DIR/seed # Crashing Seed
fi

add_target_files "$TARGET"

popd

docker login ghcr.io -u player-c3f09220 -p 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
docker pull ghcr.io/aixcc-sc/challenge-002-jenkins-cp:v3.1.0

pushd $CUR_DIR
pdl --unlock || rm -rf pipeline.lock

pdl

pd inject find_first_crash_commit.crashing_input_path 222 < "$RESOURCE_DIR/seed"
pd inject find_first_crash_commit.crashing_input_meta 222 < "$RESOURCE_DIR/crashing_input_meta"

pd inject find_first_crash_commit.target_with_source 1 < "$RESOURCE_DIR/aixcc-sc-challenge-002-jenkins-cp.tar.gz"

pd --verbose --debug-trace run
pd status
pd cat find_first_crash_commit.logs $(pd ls find_first_crash_commit.logs)
crashing_commit=$(pd cat find_first_crash_commit.crashing_commit $(pd ls find_first_crash_commit.crashing_commit)  | yq '.crashing_commit')
popd

if [ $crashing_commit == "d4860a8ac8b8c1d4642357840adb4347f7ade43a" ]; then
    echo "Success"
    exit 0
else
    echo "Failed"
    exit -1
fi
