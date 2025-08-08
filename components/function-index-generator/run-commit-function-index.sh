set -e
set -x

export TARGET_FUNCTIONS_JSONS_DIR="$TARGET_FUNCTIONS_JSONS_DIR"
export TARGET_FUNCTIONS_INDEX="$TARGET_FUNCTIONS_INDEX"

python /function-index-generator/indexer.py \
    --mode "commit" \
    --input-target-functions-json-dir $TARGET_FUNCTIONS_JSONS_DIR \
    --output-target-functions-index $TARGET_FUNCTIONS_INDEX