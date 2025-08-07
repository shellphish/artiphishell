#!/bin/sh

OSS_FUZZ_TARGET_NAME="$1"
DEFAULT_CONFIG_PATH="oss-fuzz-${OSS_FUZZ_TARGET_NAME}.yaml"
CONFIG_PATH="${2:-$DEFAULT_CONFIG_PATH}"
CONFIG_PATH=$(realpath $CONFIG_PATH)

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

get_target() {
    URL=$1
    LOCALNAME=$2
    if [ ! -d $LOCALNAME ]; then
        git clone --recursive $URL $LOCALNAME
        make cpsrc-prepare -C $LOCALNAME
    fi
    if [ ! -f $LOCALNAME.tar.gz ]; then
        tar -czf $LOCALNAME.tar.gz -C $LOCALNAME .
    fi
}

PIPELINE_RUN_DIR="pipeline-run-${OSS_FUZZ_TARGET_NAME}"
mkdir -p "$PIPELINE_RUN_DIR"
cp pipeline.yaml.template "$PIPELINE_RUN_DIR/pipeline.yaml"
cp fuzz-config-${OSS_FUZZ_TARGET_NAME}.yaml "$PIPELINE_RUN_DIR/fuzz-config.yaml"

cd "$PIPELINE_RUN_DIR"
get_target https://github.com/shellphish-support-syndicate/targets-semis-${OSS_FUZZ_TARGET_NAME}.git target

pdl --unlock || rm -rf pipeline.lock
pdl
pd inject symcts_build_symcc.target_id 1 < ./target.tar.gz
pd inject symcts_fuzz.target_fuzz_config 1 < "$CONFIG_PATH"
pd --verbose --fail-fast run
pd status

popd

set +x
