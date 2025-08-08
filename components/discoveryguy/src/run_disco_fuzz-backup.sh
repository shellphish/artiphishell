set -eux


source /shellphish/libs/test-utils/backup-handling-utils.sh

TASK_NAME=discoverry_fuzz
PRIMARY_KEY_REPO=disco_fuzz_request

if [ -z "${BACKUP_DIR}" ]; then
    echo "Available backups (in /aixcc-backups/):"
    ls /aixcc-backups/
    echo "Which backup would you like to use?"
    read -r BACKUP_NAME
    # ensure that the backup directory exists
    if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
        echo "Invalid backup directory: ${BACKUP_NAME}"
        exit 1
    fi
    BACKUP_DIR="/aixcc-backups/${BACKUP_NAME}"
fi

if [ -z "${PRIMARY_KEY_ID}" ]; then
    echo "Available ${PRIMARY_KEY_REPO}s to run: "
    echo "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the PRIMARY_KEY exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
    echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
    exit 1
fi

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${key}" $@
}
function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${key}" $@
}
function lookup_meta_key() {
    get_metadata_key $@
}

function get_codeql_block(){
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/codeql_build${key}" $@.tar.gz
}

export FUZZ_REQUEST_ID="${PRIMARY_KEY_ID}"
export FUZZ_REQUEST_META=$(get_meta discoverry_fuzz.disco_fuzz_request "${PRIMARY_KEY_ID}")
export PROJECT_ID=$(lookup_meta_key "$FUZZ_REQUEST_META" "project_id")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$FUZZ_REQUEST_META" "build_configuration_id")
export DEBUG_BUILD_ARTIFACT=$(get_fs discoverry_fuzz.debug_build_artifact "${BUILD_CONFIGURATION_ID}")
export DISCO_GUY_START_SEEDS_DIR="$BACKUP_DIR/discoverry_fuzz.discovery_guy_output_seeds/"
export DISCO_FUZZ_CRASHES="$BACKUP_DIR/discoverry_fuzz.discovery_guy_crashes/"
export HARNESSES_IN_SCOPE=$(lookup_meta_key "$FUZZ_REQUEST_META" "harnesses_in_scope")
export SEED_HASHES=$(lookup_meta_key "$FUZZ_REQUEST_META" "seed_hashes")
export FUZZ_PAYLOAD=$(lookup_meta_key "$FUZZ_REQUEST_META" "fuzz_payload")
export HARNESS_PAYLOAD=$(lookup_meta_key "$FUZZ_REQUEST_META" "harness_payload")

export FUZZING_ENGINE="libfuzzer"
export RUN_FUZZER_MODE="interactive"
export MODE="fuzz"

export TMP_DIR=$(mktemp -d -p /shared/discoveryguy/)

mkdir -p $TMP_DIR/src
mkdir -p $TMP_DIR/work
mkdir -p $TMP_DIR/out

for dir in src work out; do
    if [ -d "$DEBUG_BUILD_ARTIFACT"/$dir ]; then
         rsync -ra "$DEBUG_BUILD_ARTIFACT"/$dir/ $TMP_DIR/$dir/
    fi
done

echo "$FUZZ_PAYLOAD" | base64 -d > "$TMP_DIR/fuzz.py"
echo "$HARNESS_PAYLOAD" | base64 -d > "$TMP_DIR/harness"

echo "Look at $tmp_DIR for the output of the fuzzer"