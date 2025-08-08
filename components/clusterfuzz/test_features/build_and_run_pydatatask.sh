#!/bin/bash
set -e
set -x
set -u

add_target_files () {
    NAME="$1"
    TAR_FILE="$NAME.tar.gz"
    if [ ! -f "$TAR_FILE" ]; then
        git clone https://github.com/shellphish-support-syndicate/"$NAME".git
        pushd "$NAME"
        tar -czf "../$TAR_FILE" .
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


get_harness_name () {
    NAME=$1
    OUT=$(grep "^${NAME}" $TARGET_NAME_MAP)
    FULL_NAME=$(echo "$OUT" | cut -d',' -f3)
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


CUR_DIR=$(dirname $(realpath "${0}"))
PARENT=$(realpath "$CUR_DIR/../")
TARGET_NAME_MAP="$CUR_DIR/targets.csv"
TARGET="mupdf"

TARGET=""
SHORT=""
HARNESS=""
if [ $# -ge 1 ]; then
    if [ "$1" == "-h" ]; then
        usage
    fi
    TARGET=$(get_target_file_name "$1")
    if [ -z "$TARGET" ]; then
        echo "Target $1 not in [$(get_all_targets ',')]"
        usage
    fi
    HARNESS=$(get_harness_name "$1")
    SHORT="$1"
else
    TARGET="targets-semis-mupdf.tar.gz"
    SHORT="mupdf"
    HARNESS=$(get_harness_name "mupdf")
fi

pushd "$PARENT"
git submodule update --init --recursive
ls
docker build -t aixcc-clusterfuzz .
popd

RESOURCE_DIR=$CUR_DIR/fuzz_harness
pdl --unlock || rm -rf pipeline.lock

pdl --ignore-required

pd inject clusterfuzz_build.target_with_sources 1 < "$RESOURCE_DIR/${TARGET}.tar.gz"

echo "1337" | pd inject clusterfuzz_build.target_id 1

cat <<EOF | pd inject cluster_fuzz.harness_info 1
target_id: "1"
cp_harness_id: "222"
cp_harness_name: "$HARNESS"
EOF

if [ -d "$RESOURCE_DIR/cached/$SHORT" ]; then
    echo "Restoring cached data from $RESOURCE_DIR/cached/$SHORT"
    pd restore "$RESOURCE_DIR/cached/$SHORT" --all
fi
ipython --pdb -- "$(which pd)" --fail-fast --verbose --debug-trace run
pd status
