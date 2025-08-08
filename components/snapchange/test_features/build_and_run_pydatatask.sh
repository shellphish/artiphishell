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
        tar -czf "../$TAR_FILE" .
        SRC_PATH=$(yq '.cp_sources | keys | .[0]' project.yaml)
        cp project.yaml "../${NAME}.yaml"
        cat << EOF >> "../${NAME}.yaml"
shellphish:
  known_sources:
    linux_kernel:
      - relative_path: src/$SRC_PATH
EOF
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

CUR_DIR=$(dirname $(realpath "${0}"))
PARENT=$(realpath "$CUR_DIR/../")
TARGET_NAME_MAP="$CUR_DIR/targets.csv"
TARGET="CVE-2021-4154-CP"

TARGET=""
SHORT=""
if [ $# -ge 1 ]; then
    if [ "$1" == "-h" ]; then
        usage
    fi
    TARGET=$(get_target_file_name "$1")
    if [ -z "$TARGET" ]; then
        echo "Target $1 not in [$(get_all_targets ',')]"
        usage
    fi
    SHORT="$1"
else
    TARGET="CVE-2021-4154-CP"
fi

YAML_FILE="${TARGET}.yaml"

pushd "$PARENT"
git submodule update --init --recursive
ls
docker build -t aixcc-snapchange-fuzz .
popd

RESOURCE_DIR=$CUR_DIR/fuzz_harness
pushd "$RESOURCE_DIR"

add_target_files "$TARGET"

popd
pdl --unlock || rm -rf pipeline.lock

pdl --ignore-required
cat <<EOF | pd inject snapchange_take_snapshot.harness_info 222
project_id: "1"
cp_harness_id: "id_4"
cp_harness_name: "id_4"
cp_harness_source_path: "src/harnesses/even_justin_can_hack_this.c"
cp_harness_binary_path: "out/even_justin_can_hack_this"
EOF

echo "works: true" | pd inject  snapchange_build.project_id 1
pd inject snapchange_build.target_with_sources 1 < "$RESOURCE_DIR/${TARGET}.tar.gz"
# pd inject snapchange_build.kernel_reachability_result 1 < "$RESOURCE_DIR/kcov_filter"

cat "${RESOURCE_DIR}/${YAML_FILE}" | pd inject snapchange_build.target_metadata 1

# cat <<EOF | pd inject snapchange_build.fuzzing_request 222
# project_id: "1"
# harness_id: "222"
# reachability_request_id: "1"
# EOF
cat <<EOF | pd inject snapchange_fuzz.syzlang_grammar_input 222
syz_harness(blob buffer[in], blob_size len[blob])
EOF

if [ -d "$RESOURCE_DIR/cached/$SHORT" ]; then
    echo "Restoring cached data from $RESOURCE_DIR/cached/$SHORT"
    pd restore "$RESOURCE_DIR/cached/$SHORT" --all
fi
ipython --pdb -- "$(which pd)" --fail-fast --verbose --debug-trace run
pd status
