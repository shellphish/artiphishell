#!/bin/bash

set -e
set -u
set -x
set -o pipefail

source ../../libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PROJECT_ID="${2:-}"

PORT_NUM=${USER_PORT_NUM:-8090}

# Create temporary directory and clone OSS-Fuzz
TMP_DIR="/tmp/peek-a-boo"
mkdir -p "$TMP_DIR"
pushd "$TMP_DIR" > /dev/null

# Check if oss-fuzz already exists in this directory
if [ ! -d "$TMP_DIR/oss-fuzz" ]; then
    echo "Cloning OSS-Fuzz repository..."
    git clone https://github.com/google/oss-fuzz.git
fi
# Set OSS-Fuzz directory
OSS_FUZZ_DIR="$TMP_DIR/oss-fuzz"
popd

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

if [ -z "${PROJECT_ID}" ]; then
    echo "Available TARGET_IDs to run: "
    for f in "${BACKUP_DIR}"/oss_fuzz_project_build.project_metadata/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PROJECT_ID would you like to run?"
    read -r PROJECT_ID

    # ensure that the PROJECT_ID exists
    if [ ! -f "${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml" ]; then
        echo "Invalid PROJECT_ID: ${PROJECT_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml" ]; then
    echo "Invalid PROJECT_ID: ${PROJECT_ID}"
    exit 1
fi

export METADATA_YAML="${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml"

read -p "Choose a fuzzer aflpp or jazzer: " FUZZER_NAME
if [[ "$FUZZER_NAME" != "aflpp" && "$FUZZER_NAME" != "jazzer" ]]; then
    echo "Invalid fuzzer name. Please choose either 'aflpp' or 'jazzer'."
    exit 1
fi

if [[ $FUZZER_NAME == "aflpp" ]]; then
    echo "Using aflpp fuzzer" 
    export TARGET_SPLITTER_METADATA_YAML="${BACKUP_DIR}/aflpp_fuzz.target_split_metadata/${PROJECT_ID}.yaml"
else
    export TARGET_SPLITTER_METADATA_YAML="${BACKUP_DIR}/jazzer_fuzz.target_split_metadata/${PROJECT_ID}.yaml"
fi
# export TARGET_SPLITTER_METADATA_YAML="${BACKUP_DIR}/jazzer_fuzz.target_split_metadata/${PROJECT_ID}.yaml"

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

function extract_to_dir() {
    local tar_file="$1"
    local target_dir="$2"

    mkdir -p "$target_dir"
    tar -xzf "$tar_file" -C "$target_dir"
    echo "$target_dir"
}

export PROJECT_NAME="$(lookup_meta_key "$METADATA_YAML" ".shellphish_project_name")"
export instrumentation="$(lookup_meta_key "$METADATA_YAML" '.fuzzing_engines[0]')"

echo "PROJECT_NAME: $PROJECT_NAME"

export PROJECT_ID="$PROJECT_ID"

export CP_IMAGE_READY="$PROJECT_ID"

set +x
export TARGET_FUZZ_REPO="$(get_fs "aflpp_build.project_oss_fuzz_repo" "$PROJECT_ID")/projects/$PROJECT_NAME"

echo "TARGET_FUZZ_REPO: $TARGET_FUZZ_REPO" 
export JOB_ID="$PROJECT_ID"

# read -p "Do you want to rebuild the target? (y/n): " answer

# if [[ "$answer" =~ ^[Yy]$ ]]; then
#     echo "Rebuidling the target..."
# else

    ######################################################
    ###  Prepare artifacts to run oss-fuzz with backup ###
    ######################################################
    
    mapfile -t HARNESS_INFO_KEYS < <(lookup_meta_key "$TARGET_SPLITTER_METADATA_YAML" '.harness_info_keys[]')
    # Get all harness info keys
    if [ ${#HARNESS_INFO_KEYS[@]} -eq 0 ]; then
        echo "No harness info keys found."
        exit 1
    fi
    
    declare -A SANITIZERS    # Associative array to store sanitizers
    declare -A BUILD_CONFIGS # Associative array to store build configuration IDs

    echo -e "\nAvailable harness:"
    for i in "${!HARNESS_INFO_KEYS[@]}"; do
        HARNESS_KEY="${HARNESS_INFO_KEYS[$i]}"
        # Get the harness name using the metadata key function
        HARNESS_NAME=$(get_metadata_key "$TARGET_SPLITTER_METADATA_YAML" ".harness_infos.\"$HARNESS_KEY\".cp_harness_name")
        
        # Get build configuration ID for this harness
        # BUILD_CONFIG_ID=$(get_metadata_key "$TARGET_SPLITTER_METADATA_YAML" ".harness_infos.\"$HARNESS_KEY\".build_configuration_id")
        
        # Get sanitizer for this build configuration
        SANITIZER=$(get_metadata_key "$TARGET_SPLITTER_METADATA_YAML" ".harness_infos.\"$HARNESS_KEY\".sanitizer")
        
        # Store values in associative arrays
        SANITIZERS["$HARNESS_KEY"]="$SANITIZER"
        # BUILD_CONFIGS["$HARNESS_KEY"]="$BUILD_CONFIG_ID"

        echo "$((i+1)):  $HARNESS_NAME"
    done

    # Get user choice
    echo -e "\nSelect a harness (1-${#HARNESS_INFO_KEYS[@]}):"
    read -r CHOICE

    # Validate choice
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [ "$CHOICE" -lt 1 ] || [ "$CHOICE" -gt "${#HARNESS_INFO_KEYS[@]}" ]; then
        echo "Invalid selection."
        exit 1
    fi

    # echo "You selected: $SELECTED_KEY"

    # print all the harness info keys
    echo "Available harness info keys:"
    for i in "${!HARNESS_INFO_KEYS[@]}"; do
        HARNESS_KEY="${HARNESS_INFO_KEYS[$i]}"
        echo "$((i+1)):  $HARNESS_KEY"
       
    done
    # Get the selected key, harness name, sanitizer, and build config
    SELECTED_KEY="${HARNESS_INFO_KEYS[$((CHOICE-1))]}"
    SELECTED_HARNESS=$(get_metadata_key "$TARGET_SPLITTER_METADATA_YAML" ".harness_infos.\"$SELECTED_KEY\".cp_harness_name")
    SELECTED_SANITIZER="${SANITIZERS[$SELECTED_KEY]}"
    # SELECTED_BUILD_CONFIG="${BUILD_CONFIGS[$SELECTED_KEY]}"
    
    if [[ "$FUZZER_NAME" == "aflpp" ]]; then
        SELECTED_BUILD_CONFIG_COV=$(basename "$(ls "$BACKUP_DIR"/coverage_build_c.coverage_build_artifacts/*.tar.gz)" .tar.gz)
    else
        SELECTED_BUILD_CONFIG_COV=$(basename "$(ls "$BACKUP_DIR"/coverage_build_java.coverage_build_artifacts/*.tar.gz)" .tar.gz)
    fi

    echo "You selected: $SELECTED_HARNESS"
    echo "Sanitizer: $SELECTED_SANITIZER"
    echo "Build Configuration ID from coverage build: $SELECTED_BUILD_CONFIG_COV"
    TARGET_OUT_DIR="$OSS_FUZZ_DIR/build/out/$PROJECT_NAME/"
    # can't do this because build config id for jazzer and coverage is diferent and we want to use coveage artifacts so we do a hack
    if [[ "$FUZZER_NAME" == "aflpp" ]]; then
        export COVERAGE_ARTIFACT=$(get_fs coverage_build_c.coverage_build_artifacts "$SELECTED_BUILD_CONFIG_COV" )
    else
        export COVERAGE_ARTIFACT=$(get_fs coverage_build_java.coverage_build_artifacts "$SELECTED_BUILD_CONFIG_COV" )
    fi
    
    echo $COVERAGE_ARTIFACT
    # find "$BACKUP_DIR/coverage_build_java.coverage_build_artifacts" -type f
    # export COVERAGE_ARTIFACT="$BACKUP_DIR/coverage_build_java.coverage_build_artifacts"
    # pushd "$COVERAGE_ARTIFACT" > /dev/null
    # ls -al 
    # tarname=$(find . -type f -name "*.tar.gz")
    # tar xf $tarname .
    # rm -rf $TARGET_OUT_DIR
    mkdir -p "$TARGET_OUT_DIR"
    rsync -ra --delete $COVERAGE_ARTIFACT/artifacts/out/ $TARGET_OUT_DIR
    # popd > /dev/null

    ######################################################
    ###      Prepare seed corpus from fuzzer_sync      ###
    ######################################################


    CORPUS_DIR="/tmp/peek-a-boo/$PROJECT_NAME/$SELECTED_HARNESS"
    if [ -d "$CORPUS_DIR" ]; then
        echo "Removing existing directory: $CORPUS_DIR"
        rm -rf "$CORPUS_DIR"
    fi
    mkdir -p "$CORPUS_DIR"

    echo "Choose which corpus to use:"
    echo "1. Fuzzer sync directory"
    echo "2. Benign seeds collected from fuzzing (may not have all seeds)"
    echo "3. Custom corpus"
    echo "4. Automatically collect seeds from libpermanence"
    read -p "Enter your choice (1-4): " CORPUS_CHOICE
    case $CORPUS_CHOICE in
        1)
            echo "Using fuzzer sync directory"
            read -p "Enter the path to the unpacked fuzzer sync directory: " FUZZER_SYNC_DIR

            if [[ -n "$FUZZER_SYNC_DIR" ]]; then
                if [ ! -d "$FUZZER_SYNC_DIR" ]; then
                    echo "Error: The directory $FUZZER_SYNC_DIR does not exist."
                    exit 1
                fi
                if [[ "$FUZZER_NAME" == "aflpp" ]]; then
                    echo "NOT implemented $CORPUS_DIR"
                else
                    echo "Copying seed corpus from jazzer benign seeds to $CORPUS_DIR"
                    MINIMIZED_QUEUES=$(find "$FUZZER_SYNC_DIR" -type d -path "*/jazzer-minimized/queue" | grep -i "$SELECTED_HARNESS" | sort)

                fi
            fi
            ;;
        2)
            echo "Using benign seeds collected from fuzzing" #TODO: I can't find benign seeds for aflpp
            if [[ "$FUZZER_NAME" == "aflpp" ]]; then
                echo "Copying seed corpus from aflpp benign seeds to $CORPUS_DIR"
            else
                echo "Copying seed corpus from jazzer benign seeds to $CORPUS_DIR"
                MINIMIZED_QUEUES=$BACKUP_DIR/jazzer_fuzz_merge.benign_harness_inputs/
                # MINIMIZED_QUEUES=$(find "$FUZZER_SYNC_DIR" -type d -path "*/jazzer-minimized/queue" )
            fi
            ;;
        3)
            echo "Using custom corpus"        
            echo "Copying seed corpus from custom corpus to $CORPUS_DIR"
            read -p "Enter the absolute path to your custom corpus directory: " CUSTOM_CORPUS_DIR
            if [[ -z "$CUSTOM_CORPUS_DIR" ]]; then
                echo "Error: Custom corpus directory cannot be empty."
                exit 1
            fi
            if [ ! -d "$CUSTOM_CORPUS_DIR" ]; then
                echo "Error: The directory $CUSTOM_CORPUS_DIR does not exist."
                exit 1
            fi
            MINIMIZED_QUEUES=$CUSTOM_CORPUS_DIR/
            ;;
        4)
            echo "Automatically collecting seeds from libpermanence for $PROJECT_NAME/$SELECTED_HARNESS"        
            LIBPERM_CORPUS_DIR="$(mktemp -d)"
            SEEDS_TAR_FILE="$LIBPERM_CORPUS_DIR/${PROJECT_NAME}_${SELECTED_HARNESS}_corpus.tar.gz"
            curl -H 'Shellphish-Secret: !!artiphishell!!' "http://beatty.unfiltered.seclab.cs.ucsb.edu:31337/download_corpus/$PROJECT_NAME/$SELECTED_HARNESS" --output "$SEEDS_TAR_FILE" --fail
            
            if [ ! -f "$SEEDS_TAR_FILE" ]; then
                echo "Error: Failed to download corpus from libpermanence."
                exit 1
            fi
            echo "Extracting corpus to $LIBPERM_CORPUS_DIR"
            tar -xzf "$SEEDS_TAR_FILE" -C "$LIBPERM_CORPUS_DIR"
            rm "$SEEDS_TAR_FILE"
            MINIMIZED_QUEUES=$LIBPERM_CORPUS_DIR/
            ;;
            
        *)
            echo "Invalid choice. Please run the script again and select a valid option."
            exit 1
            ;;
    esac

    if [ -z "$MINIMIZED_QUEUES" ]; then
        echo "Warning: No queue directories found in $FUZZER_SYNC_DIR"
        exist 1
    else
        for QUEUE_DIR in $MINIMIZED_QUEUES; do
            echo "Processing queue in $QUEUE_DIR"
            rsync -ra --delete "$QUEUE_DIR/" "$CORPUS_DIR/"
        done
        TOTAL_SEEDS=$(find "$CORPUS_DIR" -type f | wc -l)
        echo "Seed corpus copied to $CORPUS_DIR with $TOTAL_SEEDS files "
    fi

    # read -p "Enter the path to the unpacked fuzzer sync directory: " FUZZER_SYNC_DIR

    # if [[ -n "$FUZZER_SYNC_DIR" ]]; then
    #     if [ ! -d "$FUZZER_SYNC_DIR" ]; then
    #         echo "Error: The directory $FUZZER_SYNC_DIR does not exist."
    #         exit 1
    #     fi
    #     if [[ "$FUZZER_NAME" == "aflpp" ]]; then
    #         echo "Copying seed corpus from aflpp benign seeds to $CORPUS_DIR"
    #     else
    #         echo "Copying seed corpus from jazzer benign seeds to $CORPUS_DIR"
    #         MINIMIZED_QUEUES=$(find "$FUZZER_SYNC_DIR" -type d -path "*/jazzer-minimized/queue" | grep -i "$SELECTED_HARNESS" | sort)

    #         if [ -z "$MINIMIZED_QUEUES" ]; then
    #             echo "Warning: No jazzer-minimized/queue directories found in $FUZZER_SYNC_DIR"
    #             exists 1
    #         else
    #             for QUEUE_DIR in $MINIMIZED_QUEUES; do
    #                 echo "Processing queue in $QUEUE_DIR"
    #                 rsync -a "$QUEUE_DIR/" "$CORPUS_DIR/"
    #             done
    #             TOTAL_SEEDS=$(find "$CORPUS_DIR" -type f | wc -l)
    #             echo "Seed corpus copied to $CORPUS_DIR with ls $TOTAL_SEEDS | wc -l"
    #         fi
    #     fi
    # fi

    ######################################################
    ###      Collect coverage target from backup       ###
    ######################################################

    
    pushd "$OSS_FUZZ_DIR" > /dev/null
    echo "===== Running coverage analysis ====="
    # Run coverage analysis with custom corpus directory
    echo "Running coverage analysis for $PROJECT_NAME with custom corpus directory..."
    rsync -ra --delete $TARGET_FUZZ_REPO/ projects/$PROJECT_NAME
    echo python3 infra/helper.py coverage "$PROJECT_NAME" --no-corpus-download --corpus-dir="$CORPUS_DIR" --fuzz-target="$SELECTED_HARNESS" --port="$PORT_NUM"
    python3 infra/helper.py coverage "$PROJECT_NAME" --no-corpus-download --corpus-dir="$CORPUS_DIR" --fuzz-target="$SELECTED_HARNESS" --port="$PORT_NUM"

    popd > /dev/null
fi
