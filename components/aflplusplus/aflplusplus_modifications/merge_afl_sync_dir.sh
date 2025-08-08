#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring
set -u # fail and exit if any variable is used before being set

CP_NAME="$1"
SYNCDIR="$2"
SEEDS_DIR="$3"
CRASHES_DIR="$4"

function handle_injected_seeds() {
    if [ "${ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS:-}" == "true" ]; then
        if [ -d "/shared/injected-seeds" ]; then
            for seed in $(/bin/ls -A /shared/injected-seeds/); do
                full_seed_path="/shared/injected-seeds/$seed"

                # Rather than just copying the seed to the streaming output path like normal, we manually have to talk to the PDT agent so that we can fake the "content_keyed_md5" hash such that we can have multiple copies of an injected seed, each with a different build configuration (ie each merge task will produce copies of all injected seeds, but with a different co-keyed metadata for each copy)

                cp $full_seed_path /tmp/tmp_seed
                echo "$JOB_ID" >> /tmp/tmp_seed

                CRASH_ID=$(md5sum /tmp/tmp_seed | cut -d ' ' -f 1)

                # First we will upload the actual seed data 
                wget -v -O- $PDT_AGENT_URL/data/aflpp_fuzz_merge/crashes/$CRASH_ID --header "Cookie: secret=$PDT_AGENT_SECRET" --post-file $full_seed_path

                cat > /tmp/crash_metadata.yaml <<EOF
architecture: $ARCHITECTURE
build_configuration_id: $ARTIPHISHELL_BUILD_CONFIGURATION_ID
cp_harness_binary_path: $ARTIPHISHELL_HARNESS_BINARY_PATH
cp_harness_name: $ARTIPHISHELL_HARNESS_NAME
fuzzer: aflplusplus
harness_info_id: $ARTIPHISHELL_HARNESS_INFO_ID
project_id: $PROJECT_ID
project_name: $ARTIPHISHELL_PROJECT_NAME
sanitizer: $SANITIZER_NAME
EOF

                # Now we upload the co-keyed metadata for this crash
                wget -v -O- $PDT_AGENT_URL/cokeydata/aflpp_fuzz_merge/crashes/meta/$CRASH_ID?hostjob=$JOB_ID --header "Cookie: secret=$PDT_AGENT_SECRET" --post-file /tmp/crash_metadata.yaml
            done
        fi
    fi
}

if [ "${ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS:-}" == "true" ]; then
    while true; do
        ls -la /shared/injected-seeds || true
        if [ -d "/shared/injected-seeds" ] && [ -n "$(/bin/ls -A /shared/injected-seeds)" ]; then
            handle_injected_seeds
            echo "🌱💉  DONE INJECTING SEEDS, SLEEPING INDEFINITELY  😴"
            sleep infinity
        else
            echo "INJECT_SEEDS was enabled but no injected seeds found at /shared/injected-seeds 🤔"
        fi
        sleep 30
    done
fi


if [ ! -e "$SYNCDIR/fuzzer_stats" ]; then
    echo "SYNCDIR does not exist yet, exiting"
    exit 0
fi

set +x
function update_files() {
    local in_dir=$1
    local out_dir=$2
    local files_modified_last_10min=$(find $in_dir -type f -mmin -10 -name 'id:*' | grep -v '.state')
    for file in $files_modified_last_10min; do
        file_sha256=$(sha256sum $file | cut -d ' ' -f 1)
        if [ ! -f "$out_dir/$file_sha256" ]; then
            echo "Copying new $file to $out_dir/$file_sha256"
            cp $file $out_dir/$file_sha256 || true
        fi
    done
}
while true; do
    # rsync all files that match 'id:*'
    echo "Syncing files for $SYNCDIR to seeds_dir=$SEEDS_DIR and crashes_dir=$CRASHES_DIR"
    # Save list of files before the sync
    find "${SEEDS_DIR}" "${CRASHES_DIR}" -type f -exec basename {} \; | sort > /tmp/files_before_sync.txt

    merge_start_time=$(date +%s)
    update_files $SYNCDIR/queue $SEEDS_DIR
    update_files $SYNCDIR/crashes $CRASHES_DIR
    merge_end_time=$(date +%s)
    merge_duration=$((merge_end_time - merge_start_time))

    # Get list of files after the sync
    find "${SEEDS_DIR}" "${CRASHES_DIR}" -type f -exec basename {} \; | sort > /tmp/files_after_sync.txt
    
    # Calculate changed files (additions and modifications)
    comm -13 "/tmp/files_before_sync.txt" "/tmp/files_after_sync.txt" > "/tmp/changed_files.txt"

    CHANGED_FILES=$(cat "/tmp/changed_files.txt" | tr '\n' ',' | sed 's/,$//')
    CORPUS_SIZE=$(wc -l /tmp/files_after_sync.txt | awk '{print $1}')
    
    telemetry-cli run \
        --attribute "crs.action.target.harness=${ARTIPHISHELL_HARNESS_NAME}" \
        --attribute "fuzz.corpus.update.method=periodic" \
        --attribute "fuzz.corpus.update.time=$(date +%s)" \
        --attribute "fuzz.corpus.size=${CORPUS_SIZE}" \
        --attribute "fuzz.corpus.additions=[${CHANGED_FILES}]" \
        --attribute "fuzz.corpus.full_snapshot=true" \
        --attribute "aflpp.seed_merge.duration=${merge_duration}" \
        "aflpp" "fuzzing" "seed_merge" "aflpp.seed_merge" || true

    sleep 20
done
