set -e
set -x
export TARGET_FUNCTIONS_JSONS_DIR="$TARGET_FUNCTIONS_JSONS_DIR"
export FUNCTIONS_BY_FILE_INDEX_JSON="$FUNCTIONS_BY_FILE_INDEX_JSON"
export TARGET_FUNCTIONS_INDEX="$TARGET_FUNCTIONS_INDEX"

export PYTHONBUFFERED=0
python /function-index-generator/indexer.py \
    --mode "full" \
    --input-target-functions-json-dir $TARGET_FUNCTIONS_JSONS_DIR \
    --output-target-functions-index $TARGET_FUNCTIONS_INDEX \
    --output-functions-by-file-index-json $FUNCTIONS_BY_FILE_INDEX_JSON