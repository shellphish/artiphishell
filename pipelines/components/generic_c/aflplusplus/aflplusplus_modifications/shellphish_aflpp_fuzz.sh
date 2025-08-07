#!/bin/bash

set -eu
set -x

# echo the original arguments
echo "################### ORIGINAL ARGUMENTS, IGNORING!!!! ###################"
echo "$@"
echo "################### ORIGINAL ARGUMENTS, IGNORING!!!! ###################"

touch "/work/${SHELLPHISH_FUZZER_NAME}.up"

CP_NAME="${SHELLPHISH_CP_NAME}"
FUZZER_NAME="${SHELLPHISH_FUZZER_NAME}"
HARNESS_BIN="${SHELLPHISH_HARNESS_BIN}"
EXTRA_ARGS_STRING="${SHELLPHISH_EXTRA_ARGS_STRING}"
SHELLPHISH_RELOCATED_HARNESS_BIN="${SHELLPHISH_RELOCATED_HARNESS_BIN:-${HARNESS_BIN}.${FUZZER_NAME}.shellphish}"

HARNESS_NAME=$(basename "$HARNESS_BIN")

export ORIG_FUZZER_NAME="${FUZZER_NAME}"

# if the ORIG_FUZZER_NAME is longer than 32 chars, use the md5sum of it instead
if [ ${#ORIG_FUZZER_NAME} -gt 32 ]; then
    export FUZZER_NAME=$(echo "${FUZZER_NAME}" | md5sum | cut -d ' ' -f 1)
else
    export FUZZER_NAME="${FUZZER_NAME}"
fi

INITIAL_CORPUS_DIR=/work/initial_corpus
export SYNC_DIR=/shared/aflpp_sync/${CP_NAME}-${HARNESS_NAME}/
mkdir -p "${SYNC_DIR}/"
echo "$ORIG_FUZZER_NAME" > "${SYNC_DIR}/$FUZZER_NAME.name"

export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1

ORIGINAL_INITIAL_CORPUS_DIR="${INITIAL_CORPUS_DIR}"

# fix up ASAN options
if [ -n "${ASAN_OPTIONS:-}" ]; then
    export ASAN_OPTIONS="${ASAN_OPTIONS},abort_on_error=1,symbolize=0"
fi

while true; do
    # if the name matches main_*, then we are the main node
    if [[ "${ORIG_FUZZER_NAME}" == main_* ]]; then
        fuzzer_name_flag="-M ${ORIG_FUZZER_NAME}"
    else
        fuzzer_name_flag="-S ${FUZZER_NAME}"
    fi
    
    /shellphish/libfreedom/bin/afl-fuzz \
        -i "${INITIAL_CORPUS_DIR}" \
        -o "${SYNC_DIR}/" \
        ${fuzzer_name_flag} \
        ${EXTRA_ARGS_STRING} \
        -- "${SHELLPHISH_RELOCATED_HARNESS_BIN}" || true
    /shellphish/libfreedom/bin/afl-fuzz \
        -i "-" \
        -o "${SYNC_DIR}/" \
        ${fuzzer_name_flag} \
        ${EXTRA_ARGS_STRING} \
        -- "${SHELLPHISH_RELOCATED_HARNESS_BIN}" || true
    set +e # if we've errored during aflpp, all bets are off, ignore all further errors, we must stay alive at all costs

    rm -rf "${INITIAL_CORPUS_DIR}/*"
    for arg in ${EXTRA_ARGS_STRING}; do
        if [ -d "${arg}" ]; then
            for f in ${arg}/*; do
                if [ ! -f "${f}" ]; then
                    continue
                fi
                SHOWMAP_RESULT_INPUT_IS_CRASHING=$(/shellphish/libfreedom/bin/afl-showmap -q -o /dev/null -- "${HARNESS_BIN}" "${f}" 2>&1)
                SHOWMAP_RESULT=$?
                if [ "${SHOWMAP_RESULT}" -eq 0 ]; then
                    echo "Found a non-crashing input, copying to new starting corpus"
                    cp "${f}" "${INITIAL_CORPUS_DIR}/"
                fi
            done
        fi
    done
    sleep 10
done
