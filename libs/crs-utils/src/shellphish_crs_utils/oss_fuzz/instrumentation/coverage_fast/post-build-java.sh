#!/bin/bash

set -eu

CURR_DIR=$(pwd)
echo "CURR_DIR is $CURR_DIR"

export BUILT_PROJECT_PATH=$BUILT_PROJECT_PATH

export PYTHON_INTERPRETER=${PYTHON_INTERPRETER:-python3}
set -x
echo "=== Running antlr4-guy ==="
mkdir -p $OUT/antlr-out/
export OUT_FULL_FUNCTIONS_JSONS=$OUT/antlr-out/antlr-guy-results
export OUT_FULL_FUNCTIONS_INDEX=$OUT/antlr-out/func-index-results
if [ "x${ARTIPHISHELL_FULL_FUNCTIONS_JSONS:-}" != "x" ] && [ -d "${ARTIPHISHELL_FULL_FUNCTIONS_JSONS:-}" ]; then
    echo "=== ARTIPHISHELL_FULL_FUNCTIONS_JSONS is set, rsyncing ==="
    rsync -rav $ARTIPHISHELL_FULL_FUNCTIONS_JSONS/ $OUT_FULL_FUNCTIONS_JSONS/
else
    echo "=== ARTIPHISHELL_FULL_FUNCTIONS_JSONS is not set, building from scratch ==="
    if [ ! -f "$OUT_FULL_FUNCTIONS_JSONS.done" ]; then
        rm -rf $OUT_FULL_FUNCTIONS_JSONS
        echo "=== $OUT_FULL_FUNCTIONS_JSONS.done does not exist, building from scratch ==="
        $PYTHON_INTERPRETER $ARTIPHISHELL_DIR/components/antlr4-guy/run-java.py --mode=full --project-source=. --canonical-build-artifact "$BUILT_PROJECT_PATH" --output-dir=$OUT_FULL_FUNCTIONS_JSONS 2>&1 | tee $OUT/antlr4-guy.log
        touch "$OUT_FULL_FUNCTIONS_JSONS.done"
    fi
fi
if [ -f "${ARTIPHISHELL_FULL_FUNCTIONS_INDEX:-}" ]; then
    echo "=== ARTIPHISHELL_FULL_FUNCTIONS_INDEX is set, rsyncing ==="
    rsync -rav $ARTIPHISHELL_FULL_FUNCTIONS_INDEX $OUT_FULL_FUNCTIONS_INDEX
else
    echo "=== ARTIPHISHELL_FULL_FUNCTIONS_INDEX is not set, building from scratch ==="
    if [ ! -f "$OUT_FULL_FUNCTIONS_INDEX.done" ]; then
        echo "=== OUT_FULL_FUNCTIONS_INDEX is not set, building from scratch ==="
        rm -rf $OUT_FULL_FUNCTIONS_INDEX
        
        $PYTHON_INTERPRETER $ARTIPHISHELL_DIR/components/function-index-generator/indexer.py --mode="full" --input-target-functions-json-dir=$OUT_FULL_FUNCTIONS_JSONS --output-target-functions-index=$OUT_FULL_FUNCTIONS_INDEX --output-functions-by-file-index-json=/tmp/heckthis
        touch "$OUT_FULL_FUNCTIONS_INDEX.done"
    fi
fi
$PYTHON_INTERPRETER $ARTIPHISHELL_DIR/libs/crs-utils/src/shellphish_crs_utils/oss_fuzz/instrumentation/jazzer/find_instrumentation.py --func_report=$OUT_FULL_FUNCTIONS_INDEX --packages_in_scope=$OUT/antlr-out/classes_in_scope.json
$PYTHON_INTERPRETER $INSTRUMENTATION_DIR/extract_classes.py