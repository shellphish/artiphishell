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
        tar -czvf "../$TAR_FILE" .
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
    exit 1
fi

YAML_FILE="${TARGET}.yaml"

pushd "$PARENT"
git submodule update --init --recursive
ls
docker build -t aixcc-syzgrammar-gen .
popd

RESOURCE_DIR=$CUR_DIR/target_stuffs
pushd "$RESOURCE_DIR"

add_target_files "$TARGET"

popd
pdl --unlock || rm -rf pipeline.lock

pdl --ignore-required
cat <<EOF | pd inject syz_grammar_generate.harness_info 1
project_id: "1"
cp_harness_id: "id_4"
cp_harness_name: "id_4"
cp_harness_source_path: "src/harnesses/even_nilo_can_hack_this.c"
cp_harness_binary_path: "out/even_nilo_can_hack_this"
EOF

pd inject syz_grammar_generate.target_with_sources 1 < "$RESOURCE_DIR/${TARGET}.tar.gz"

cat "${RESOURCE_DIR}/${YAML_FILE}" | pd inject syz_grammar_generate.target_metadata 1


if [ -d "$RESOURCE_DIR/cached/$SHORT" ]; then
    echo "Restoring cached data from $RESOURCE_DIR/cached/$SHORT"
    pd restore "$RESOURCE_DIR/cached/$SHORT" --all
fi

ipython --pdb -- "$(which pd)" --fail-fast --verbose --debug-trace run
pd status
