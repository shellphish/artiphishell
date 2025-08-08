#! /bin/bash

set -x

export LIBFUZZER_INSTANCE_UNIQUE_NAME=${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/
export ARTIPHISHELL_FUZZER_SYNC_PATH="/shared/fuzzer_sync/$LIBFUZZER_INSTANCE_UNIQUE_NAME/"

export LIBFUZZER_BENIGN_SEEDS_DIR="$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-minimized/queue/"
export LIBFUZZER_CRASHES_DIR="$ARTIPHISHELL_FUZZER_SYNC_PATH/libfuzzer-all/crashes/"

mkdir -p $LIBFUZZER_BENIGN_SEEDS_DIR $LIBFUZZER_CRASHES_DIR

PDT_SEEDS_DIR="${PDT_SEEDS_DIR}"
PDT_CRASHES_DIR="${PDT_CRASHES_DIR}"

function handle_injected_seeds() {
    if [ "${ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS}" == "true" ]; then
        if [ -d "/shared/injected-seeds" ]; then
            for seed in $(/bin/ls -A /shared/injected-seeds/); do
                full_seed_path="/shared/injected-seeds/$seed"

                # Rather than just copying the seed to the streaming output path like normal, we manually have to talk to the PDT agent so that we can fake the "content_keyed_md5" hash such that we can have multiple copies of an injected seed, each with a different build configuration (ie each merge task will produce copies of all injected seeds, but with a different co-keyed metadata for each copy)

                cp $full_seed_path /tmp/tmp_seed
                echo "$JOB_ID" >> /tmp/tmp_seed

                CRASH_ID=$(md5sum /tmp/tmp_seed | cut -d ' ' -f 1)

                # First we will upload the actual seed data 
                wget -v -O- $PDT_AGENT_URL/data/libfuzzer_fuzz_merge/crashing_harness_inputs/$CRASH_ID --header "Cookie: secret=$PDT_AGENT_SECRET" --post-file $full_seed_path

                cat > /tmp/crash_metadata.yaml <<EOF
architecture: $ARCHITECTURE
build_configuration_id: $ARTIPHISHELL_BUILD_CONFIGURATION_ID
cp_harness_binary_path: $ARTIPHISHELL_HARNESS_BINARY_PATH
cp_harness_name: $ARTIPHISHELL_HARNESS_NAME
fuzzer: libfuzzer
harness_info_id: $ARTIPHISHELL_HARNESS_INFO_ID
project_id: $PROJECT_ID
project_name: $ARTIPHISHELL_PROJECT_NAME
sanitizer: $SANITIZER_NAME
EOF

                # Now we upload the co-keyed metadata for this crash
                wget -v -O- $PDT_AGENT_URL/cokeydata/libfuzzer_fuzz_merge/crashing_harness_inputs/meta/$CRASH_ID?hostjob=$JOB_ID --header "Cookie: secret=$PDT_AGENT_SECRET" --post-file /tmp/crash_metadata.yaml
            done
        fi
    fi
}

if [ "${ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS}" == "true" ]; then
    while true; do
        ls -la /shared/injected-seeds || true
        if [ -d "/shared/injected-seeds" ]; then
            handle_injected_seeds
            echo "🌱💉  DONE INJECTING SEEDS, SLEEPING INDEFINITELY  😴"
            sleep infinity
        else
            echo "INJECT_SEEDS was enabled but no injected seeds found at /shared/injected-seeds 🤔"
        fi
        sleep 30
    done
fi

function update_files() {
    local in_dir=$1
    local out_dir=$2
    local files_modified_last_10min=$(find $in_dir -type f -mmin -6 )
    for file in $files_modified_last_10min; do
        file_sha256=$(sha256sum $file | cut -d ' ' -f 1)
        if [ ! -f "$out_dir/$file_sha256" ]; then
            echo "Copying new..... $file to $out_dir/$file_sha256"
            cp $file $out_dir/$file_sha256 || true
        fi
    done
}
while true; do
    
    # Save list of files before the sync
    find "${PDT_SEEDS_DIR}" "${PDT_CRASHES_DIR}" -type f -exec basename {} \; | sort > /tmp/files_before_sync.txt

    echo "All benign seeds after minimization: $(ls "$LIBFUZZER_BENIGN_SEEDS_DIR" | wc -l)"
    echo "All crashes before minimization: $(ls "$LIBFUZZER_CRASHES_DIR" | wc -l)"

    echo "Syncing files for $ARTIPHISHELL_FUZZER_SYNC_PATH to PDT_SEEDS_DIR=$PDT_SEEDS_DIR and PDT_CRASHES_DIR=$PDT_CRASHES_DIR"
    update_files $LIBFUZZER_BENIGN_SEEDS_DIR $PDT_SEEDS_DIR
    update_files $LIBFUZZER_CRASHES_DIR $PDT_CRASHES_DIR
    
    # Get list of files after the sync
    find "${PDT_SEEDS_DIR}" "${PDT_CRASHES_DIR}" -type f -exec basename {} \; | sort > /tmp/files_after_sync.txt
    
    # Calculate changed files (additions and modifications)
    comm -13 "/tmp/files_before_sync.txt" "/tmp/files_after_sync.txt" > "/tmp/changed_files.txt"
    CHANGED_FILES=$(cat "/tmp/changed_files.txt" | tr '\n' ',' | sed 's/,$//')

    telemetry-cli run \
        --attribute "crs.action.target.harness=${ARTIPHISHELL_HARNESS_NAME}" \
        --attribute "fuzz.corpus.update.method=periodic" \
        --attribute "fuzz.corpus.update.time=$(date +%s)" \
        --attribute "fuzz.corpus.size=$(wc -l /tmp/files_after_sync.txt | awk '{print $1}')" \
        --attribute "fuzz.corpus.additions=[${CHANGED_FILES}]" \
        --attribute "fuzz.corpus.full_snapshot=true" \
        --attribute "libfuzzer.seed_merge.duration=${merge_duration}" \
        "libfuzzer" "fuzzing" "seed_merge" "libfuzzer.seed_merge" || true

    # TODO: see how telem works for libfuzzer

    echo "sleeping for 30 secs!"
    sleep 30
done
