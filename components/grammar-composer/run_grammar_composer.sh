#!/bin/bash

set -x
set -e
set -u

# export to spot undefined variables
export LANGUAGE=$LANGUAGE
export PROJECT_METADATA_PATH=$PROJECT_METADATA_PATH
export HARNESS_INFO_PATH=$HARNESS_INFO_PATH
export COVERAGE_BUILD_ARTIFACT=$COVERAGE_BUILD_ARTIFACT
export FUNCTIONS_INDEX_PATH=$FUNCTIONS_INDEX_PATH
export FUNCTIONS_JSONS_DIR_PATH=$FUNCTIONS_JSONS_DIR_PATH

export ARTIPHISHELL_PROJECT_NAME=$ARTIPHISHELL_PROJECT_NAME
export ARTIPHISHELL_PROJECT_ID=$ARTIPHISHELL_PROJECT_ID
export ARTIPHISHELL_HARNESS_NAME=$ARTIPHISHELL_HARNESS_NAME
export ARTIPHISHELL_HARNESS_INFO_ID=$ARTIPHISHELL_HARNESS_INFO_ID
export ARTIPHISHELL_FUZZER_SYNC_BASE_DIR="/shared/fuzzer_sync"
export ARTIPHISHELL_FUZZER_SYNC_DIR="${ARTIPHISHELL_FUZZER_SYNC_BASE_DIR}/${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/"

export ARTIPHISHELL_GRAMMARS_SYNC_PATH="${ARTIPHISHELL_FUZZER_SYNC_DIR}/sync-grammars/nautilus-python"
mkdir -p $ARTIPHISHELL_GRAMMARS_SYNC_PATH

mkdir -p /shared/grammar-composer/$ARTIPHISHELL_PROJECT_ID/
TMPDIR=$(mktemp -d -p /shared/grammar-composer/$ARTIPHISHELL_PROJECT_ID/)
rsync -ra "$COVERAGE_BUILD_ARTIFACT"/ "$TMPDIR"/
export PROJECT_DIR=$TMPDIR

function run_grammar_composer() {
    python3 /shellphish/grammar-composer/run_grammar_composer.py
}

update_token_grammar() {
    while true; do
        sleep 1800
        (
            tmpfile=$(mktemp)
            python /shellphish/grammar-composer/create_token_grammar.py "$tmpfile" "$ARTIPHISHELL_GRAMMARS_SYNC_PATH"
            md5=$(md5sum "$tmpfile" | cut -d' ' -f1)
            dest="$ARTIPHISHELL_GRAMMARS_SYNC_PATH/token_grammar_$md5.py"
            [ ! -e "$dest" ] && cp "$tmpfile" "$dest"
            rm "$tmpfile"
        ) || true
    done
}

run_grammar_composer &
update_token_grammar &
wait

rm -rf $TMPDIR