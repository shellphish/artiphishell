#!/usr/bin/bash

docker login ghcr.io -u player-c3f09220 -p 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

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
    TARGET="targets-semis-aixcc-sc-challenge-002-jenkins-cp"
fi

pushd $PARENT
docker build -t aixcc-test_harness_jenkins .
popd

RESOURCE_DIR=$CUR_DIR/fuzz_jenkins
pushd $RESOURCE_DIR

if [ ! -f targets-semis-aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git
    pushd targets-semis-aixcc-sc-challenge-002-jenkins-cp
    sed -i 's/env bash/env bash\nset +e\nset -x/g' ./run.sh

    make cpsrc-prepare
    tar -cvzf ../targets-semis-aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    popd
    rm -rf ./targets-semis-aixcc-sc-challenge-002-jenkins-cp
fi

if [ ! -f jenkins_jazzer_seeds.tar.gz ]; then
    mkdir -p jenkins_jazzer_seeds
    pushd jenkins_jazzer_seeds
    echo "foobar" > 1
    echo "eC1ldmlsLWJhY2tkb29yAGJyZWFraW4gdGhlIGxhdwBqYXp6ZQ==" | base64 -d > 1 # Crashing Seed
    tar -czvf ../jenkins_jazzer_seeds.tar.gz .
    popd
    rm -rf ./jenkins_jazzer_seeds
fi

if [ ! -f strings.tar.gz ]; then
    mkdir -p strings
    pushd strings
    cp ../dict.json ./java-string-literals.json
    tar -czvf ../strings.tar.gz .
    popd
    rm -rf strings
fi

add_target_files "$TARGET"

popd
pdl --unlock || rm -rf pipeline.lock

pdl --ignore-required
cat <<EOF | pd inject jenkins_jazzer_fuzz.harness_info 222
project_id: "1"
cp_harness_id: "id_1"
cp_harness_name: "JenkinsTwo"
cp_harness_source_path: "src/jenkins-harnesses/jenkins-harness-two/src/main/java/com/aixcc/jenkins/harnesses/twoJenkinsTwo.java"
cp_harness_binary_path: "out/harnesses/two/aixcc-harness.jar"
EOF

pd inject jenkins_build_for_jazzer.target_with_sources 1 < "$RESOURCE_DIR/${TARGET}.tar.gz"
pd inject jenkins_jazzer_no_codeql_fuzz.full_function_index 1 <  "$RESOURCE_DIR/index.json"
cat <<EOF | pd inject jenkins_jazzer_no_codeql_fuzz.fuzzing_request 222
project_id: "1"
harness_id: "222"
reachability_request_id: "1"
EOF
cat <<EOF | pd inject jenkins_build_for_jazzer.cp_image_ready 1
ready
EOF

pd --verbose run

#ipython --pdb -- "$(which pd)" run
pd status
