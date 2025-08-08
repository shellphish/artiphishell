#!/bin/bash

set -x
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# one argument is required
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <fuzzer> <target_name> <backup_folder>"
    exit 1
fi
export FUZZER="$1"
export TARGET="$2"
export USE_LLM_API=0
export BIN_DIR=""
export TEST_FOLDER="$SCRIPT_DIR"
export BACKUP_FOLDER="$(realpath "$3")"
# generate three tmp folders in ./tmp/ for seeds_to_triage_XXXX, info_extraction_request_XXXX, and events_XXXX
mkdir -p ./tmp/$TARGET/seeds
mkdir -p ./tmp/$TARGET/events

export SEEDS_TO_TRIAGE_DIR=$(mktemp -d -p ./tmp/$TARGET seeds/seeds_to_triage_$(date +%s)_XXXX)
export EVENTS_DIR=$(mktemp -d -p ./tmp/$TARGET events/events_$(date +%s)_XXXX)

SHARED_TARGET_DIR="/shared/grammar_guy/fuzz/$TARGET-local/built_target"

# dont taint backup
rm -rf "${SHARED_TARGET_DIR}"
mkdir -p "${SHARED_TARGET_DIR}"
mkdir -p ./tmp/$TARGET/harness_info
mkdir -p ./tmp/$TARGET/functions_index
mkdir -p ./tmp/$TARGET/functions_jsons_dir
mkdir -p ./tmp/$TARGET/info_extraction_requests

# cp -r "${BACKUP_FOLDER}/grammar_guy_fuzz.harness_info/1878c5384f71789dad207d0d576c055f.yaml" "./tmp/$TARGET/harness_info/"
# cp -r "${BACKUP_FOLDER}/grammar_guy_fuzz.functions_index/1" "./tmp/$TARGET/functions_index/"
cp -r "${BACKUP_FOLDER}/grammar_guy_fuzz.info_extraction_requests/1.yaml" "./tmp/$TARGET/info_extraction_requests/"

if [ ! -d "./tmp/$TARGET/functions_jsons_dir/1" ]; then
    pushd ./tmp/$TARGET/functions_jsons_dir/
    unar "${BACKUP_FOLDER}/grammar_guy_fuzz.functions_jsons_dir/1.tar.gz"
    popd
fi

pushd "${SHARED_TARGET_DIR}"
unar "${BACKUP_FOLDER}/coverage_build.target_built_with_coverage/1.tar.gz"
popd 


PYTHONUNBUFFERED=TRUE ipython --pdb -- ../src/grammar_guy/main.py \
                    -i 1 \
                    -n 200 \
                    -b   "${BACKUP_FOLDER}/grammar_guy_fuzz.harness_info/1878c5384f71789dad207d0d576c055f.yaml" \
                    -idx "${BACKUP_FOLDER}/grammar_guy_fuzz.functions_index/1" \
                    -f   "${BACKUP_FOLDER}/grammar_guy_fuzz.info_extraction_requests/1.yaml" \
                    -t   "${SHARED_TARGET_DIR}/1" \
                    -jd  "${TEST_FOLDER}/tmp/$TARGET/functions_jsons_dir/1" \
                    -ifd "${TEST_FOLDER}/$SEEDS_TO_TRIAGE_DIR" \
                    -s   "${TEST_FOLDER}/$EVENTS_DIR" \
                    -fuzz "$FUZZER"
