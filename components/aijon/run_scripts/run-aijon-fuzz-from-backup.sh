#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

INSTR_ARTIFACT=""
BUILD_ARTIFACT=""
SEED_CORPUS=""
POSITIONAL_ARGS=()

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed-corpus)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --seed-corpus requires a file path."
                exit 1
            fi
            if [[ -z "$1" || "$1" == --* ]]; then
                echo "Error: --seed-corpus requires a file path."
                exit 1
            fi
            SEED_CORPUS="$1"
            shift
            ;;
        --instr-artifact)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --instr-artifact requires a directory path."
                exit 1
            fi
            if [[ -z "$1" || "$1" == --* ]]; then
                echo "Error: --instr-artifact requires a directory path."
                exit 1
            fi
            INSTR_ARTIFACT="$1"
            shift
            ;;
        --build-artifact)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --build-artifact requires a directory path."
                exit 1
            fi
            if [[ -z "$1" || "$1" == --* ]]; then
                echo "Error: --build-artifact requires a directory path."
                exit 1
            fi
            BUILD_ARTIFACT="$1"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--instr-artifact <dir>] [--build-artifact <dir>] [--seed-corpus <zip_file|directory>] <backup_dir> <build_config_id>"
            exit 0
            ;;
        --*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ -n "$INSTR_ARTIFACT" ] && [ ! -d "$INSTR_ARTIFACT" ]; then
    echo "Error: --instr-artifact must be a valid directory."
    exit 1
fi

if [ -n "$BUILD_ARTIFACT" ] && [ ! -d "$BUILD_ARTIFACT" ]; then
    echo "Error: --build-artifact must be a valid directory."
    exit 1
fi

if [ -n "$SEED_CORPUS" ]; then
    if [ -d "$SEED_CORPUS" ]; then
        # We'll zip it up if it's a directory
        DIRNAME=$(basename "$SEED_CORPUS")
        pushd "$SEED_CORPUS"
        zip -r "${DIRNAME}.zip" ./*
        popd
        SEED_CORPUS="${SEED_CORPUS}/${DIRNAME}.zip"
    elif [ -f "$SEED_CORPUS" ]; then
        if [[ "$SEED_CORPUS" != *.zip ]]; then
            echo "Error: --seed-corpus must be a zip file or a directory."
            exit 1
        fi
    else
        echo "Error: --seed-corpus must be a valid file or directory."
        exit 1
    fi
fi

BACKUP_DIR="${POSITIONAL_ARGS[0]:-}"
HARNESS_INFO_ID="${POSITIONAL_ARGS[1]:-}"

TASK_NAME=aijon_fuzz_aflpp
PRIMARY_KEY_REPO=harness_info

if [ -z "${BACKUP_DIR}" ]; then
    num_backups=$(ls /aixcc-backups/ | wc -l)
    if [ "$num_backups" -eq 0 ]; then
        echo "No backups found in /aixcc-backups/"
        exit 1
    elif [ "$num_backups" -eq 1 ]; then
        BACKUP_NAME=$(ls /aixcc-backups/)
        echo "Only one backup found: ${BACKUP_NAME}"
    else
        echo "Available backups (in /aixcc-backups/):"
        ls /aixcc-backups/
        echo "Which backup would you like to use?"
        read -r BACKUP_NAME
        # ensure that the backup directory exists
        if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
            echo "Invalid backup directory: ${BACKUP_NAME}"
            exit 1
        fi
    fi
    BACKUP_DIR="/aixcc-backups/${BACKUP_NAME}"
fi

if [ -z "${HARNESS_INFO_ID}" ]; then
    num_build_configs=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}" | wc -l)
    if [ "$num_build_configs" -eq 0 ]; then
        echo "No harness infos found in ${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
        exit 1
    elif [ "$num_build_configs" -eq 1 ]; then
        yaml_file=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}")
        HARNESS_INFO_ID="${yaml_file%.yaml}"
        echo "Only one harness info found: ${HARNESS_INFO_ID}"
    else
        echo "Available HARNESS_INFOs to run: "
        for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
            harness_name=$(yq '.cp_harness_name' "$f")
            echo "$(basename "${f%.yaml}") - ${harness_name}"
        done
        echo "Which HARNESS_INFO would you like to run?"
        read -r HARNESS_INFO_ID
    fi

    # ensure that the HARNESS_INFO_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
        echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
        exit 1
    fi
fi

# if the CRASHING_INPUT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
    echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
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

export HARNESS_INFO_ID="$HARNESS_INFO_ID"
export HARNESS_INFO=$(get_blob "aijon_fuzz_aflpp.harness_info" "${HARNESS_INFO_ID}.yaml")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO" ".build_configuration_id")
export CRS_PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO" ".project_name")
export PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO" ".project_id")
export DISCOVERY_GUY_CORPUS_DIR=$(get_fs "aijon_fuzz_aflpp.aijon_discovery_guy_corpus_dir" "$BUILD_CONFIGURATION_ID")

export HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO" ".cp_harness_name")
if [ -n "$BUILD_ARTIFACT" ]; then
    export BUILD_ARTIFACT="$BUILD_ARTIFACT"
else
    export BUILD_ARTIFACT=$(get_fs "aijon_fuzz_aflpp.aijon_build_artifact_dir" "$BUILD_CONFIGURATION_ID")
fi
if [ ! -d "$BUILD_ARTIFACT/artifacts/out" ]; then
    echo "Build artifact directory does not contain artifacts/out directory: $BUILD_ARTIFACT"
    exit 1
fi

export BUILD_SANITIZER=$(lookup_meta_key "$HARNESS_INFO" ".sanitizer")

if [ -n "$INSTR_ARTIFACT" ]; then
    export INSTRUMENTATION_ARTIFACTS="$INSTR_ARTIFACT"
else
    export INSTRUMENTATION_ARTIFACTS=$(get_fs "aijon_build.aijon_instrumentation_artifact" "$HARNESS_INFO_ID")
fi

PROJECT_METADATA=$(get_blob "dyva_agent.project_metadata" "$PROJECT_ID.yaml")
export LANGUAGE=$(lookup_meta_key "$PROJECT_METADATA" ".language")

if [ ! -d /shared/artiphishell-ossfuzz-targets/projects ]; then
    echo "Directory /shared/artiphishell-ossfuzz-targets/projects does not exist."
    echo "Run : git clone shellphish-support-syndicate/artiphishell-ossfuzz-targets /shared/artiphishell-ossfuzz-targets"
    exit 1
fi
export OSS_FUZZ_PROJECT_DIR="/shared/artiphishell-ossfuzz-targets/projects/${CRS_PROJECT_NAME}"
mkdir -p "${OSS_FUZZ_PROJECT_DIR}"

rsync -ravz "${BUILD_ARTIFACT}" "${OSS_FUZZ_PROJECT_DIR}"

if [ -n "$SEED_CORPUS" ]; then
    # This should be a zip file
    cp "$SEED_CORPUS" "${INSTRUMENTATION_ARTIFACTS}/artifacts/out/${HARNESS_NAME}_seed_corpus.zip"
fi
/aijon/run_scripts/run-aijon-fuzz.sh
