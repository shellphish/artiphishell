#!/bin/bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
CRS_ROOT="$SCRIPT_PARENT_DIR/"

if [ -z "$1" ]; then
    echo "Usage: $0 <project_name>"
    exit 1
fi

function retry_until_success() {
    local CMD="$@"
    local RETRIES=0
    local CMD_NAME=$(echo "$CMD" | cut -d' ' -f1-3)

    while [ $RETRIES -lt $MAX_RETRIES ]; do
      if [ ! -z "$OUTPUT_FILE" ]; then
        $CMD > $OUTPUT_FILE && return 0
        cat $OUTPUT_FILE
      else
        $CMD && return 0
      fi
      RETRIES=$((RETRIES+1))
      echo "Retrying failed command $CMD_NAME ($RETRIES/$MAX_RETRIES) in $INTERVAL seconds..."
      sleep $INTERVAL
    done
    return 0
}

PROJECT_NAME="$1"

mkdir -p $SCRIPT_DIR/.shellphish

META_REPO="${META_REPO:=https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-meta}"

META_REPO_PATH="$SCRIPT_DIR/.shellphish/artiphishell-ossfuzz-meta"
if [ ! -d "$META_REPO_PATH" ]; then
    git clone $META_REPO $META_REPO_PATH
fi

pushd $META_REPO_PATH

git fetch
git checkout origin/main

SEEDS_DIR=$(mktemp -d)
SEEDS_DIR="$SEEDS_DIR/injected-seeds"
mkdir -p $SEEDS_DIR

if [ ! -d "$PROJECT_NAME/cpv_info" ]; then
    echo "⚠️ ============================================== ⚠️"
    echo "⚠️     NO CRASHES FOUND FOR PROJECT $PROJECT_NAME    ⚠️"
    echo "⚠️     Project directory does not exist             ⚠️" 
    echo "⚠️                                                  ⚠️"
    echo "⚠️  Please check if crashes exist at:              ⚠️"
    echo "⚠️  $META_REPO/tree/main/$PROJECT_NAME            ⚠️"
    echo "⚠️  Crashes should be named 'crashing_inp'         ⚠️"
    echo "⚠️ ============================================== ⚠️"
    exit 1
fi

pushd $PROJECT_NAME/cpv_info

# Initialize counter for seed naming
seed_counter=0

# Find all directories and check for crashing_inp
for dir in */; do
    if [ -f "${dir}crashing_inp" ]; then
        # Create padded counter string (6 digits)
        padded_counter=$(printf "%06d" $seed_counter)
        
        # Copy crash file with new name format
        cp "${dir}crashing_inp" "$SEEDS_DIR/id:${padded_counter}"
        
        # Increment counter using let command with error checking
        let "seed_counter=seed_counter+1" || true
    fi
done

# If no files in SEEDS_DIR, exit with error
if [ -z "$(ls -A $SEEDS_DIR)" ]; then
    echo "⚠️ ============================================== ⚠️"
    echo "⚠️     NO CRASHES FOUND FOR PROJECT $PROJECT_NAME    ⚠️"
    echo "⚠️     No crashing inputs were found               ⚠️"
    echo "⚠️                                                  ⚠️"
    echo "⚠️  Please check if crashes exist at:              ⚠️"
    echo "⚠️  $META_REPO/tree/main/$PROJECT_NAME            ⚠️"
    echo "⚠️  Crashes should be named 'crashing_inp'         ⚠️"
    echo "⚠️ ============================================== ⚠️"
    exit 1
fi

PODS=$(kubectl get pods -n default -l name=host-config -o jsonpath='{.items[*].metadata.name}')

export MAX_RETRIES=10
export INTERVAL=10

for POD in $PODS; do
    retry_until_success kubectl cp $SEEDS_DIR $POD:/shared/ --retries=5 || true

done

popd
