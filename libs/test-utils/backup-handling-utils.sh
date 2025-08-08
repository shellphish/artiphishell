#!/bin/bash

function get_filesystem_repo_entry() {
    local repo_dir="${1}"
    if [ -d "${repo_dir}.__footprint.1/" ]; then
        repo_dir="${repo_dir}.__footprint.1"
    fi
    local key="${2}"
    if [ ! -d "${repo_dir}/${key}" ]; then
        mkdir -p "${repo_dir}/${key}" > /dev/null
        pushd "${repo_dir}/${key}" > /dev/null
        tar -xf "${repo_dir}/${key}.tar.gz" > /dev/null
        popd > /dev/null
    fi
    echo "${repo_dir}/${key}"
}

function get_metadata_repo_entry() {
    local repo_dir="${1}"
    local key="${2}"

    # if they key does not already end in .yaml (normally), then append it
    if [[ "${key}" != *.yaml ]]; then
        key="${key}.yaml"
    fi
    if [ ! -f "${repo_dir}/${key}" ]; then
        echo "Invalid metadata key: ${key}" > /dev/stderr
        exit 1
    fi
    echo "${repo_dir}/${key}"
}
function get_blob_repo_entry() {
    local repo_dir="${1}"
    local key="${2}"

    # if they key does not already end in .yaml (normally), then append it
    if [ ! -f "${repo_dir}/${key}" ]; then
        echo "Invalid metadata key: ${key}" > /dev/stderr
        exit 1
    fi
    echo "${repo_dir}/${key}"
}

function get_metadata_key() {
    local metadata_path="${1}"
    local expr="${2}"
    yq -r "${expr}" "${metadata_path}"
}

function get_backup_dir() {
    local backup_dir="$1"
    if [ -z "$backup_dir" ]; then
        echo "Available backups (in /aixcc-backups/):" 1>&2
        ls /aixcc-backups/ 1>&2
        echo "Which backup would you like to use?" 1>&2
        read -r BACKUP_NAME
        # ensure that the backup directory exists
        if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
            echo "Invalid backup directory: ${BACKUP_NAME}"
            exit 1
        fi
        backup_dir="/aixcc-backups/${BACKUP_NAME}"
    fi
    echo "${backup_dir}"
}

function get_primary_key() {
    local primary_key="${1}"
    local backup_dir="${2}"
    local repo_dir="${3}"

    
    if [ -z "${primary_key}" ]; then
        echo "Available primary keys to run (${repo_dir}): " 1>&2
        for f in "${BACKUP_DIR}/${repo_dir}"/*; do
            local basename=$(basename "${f}")
            local stripped_yaml="${basename%.yaml}"
            local stripped_tar_gz="${stripped_yaml%.tar.gz}"
            echo "$stripped_tar_gz" 1>&2
        done
        echo "Which primary_key(${repo_dir}) would you like to run?" 1>&2
        read -r primary_key

        # ensure that the primary_key exists
        if [ ! -f "${BACKUP_DIR}/${repo_dir}/${primary_key}.yaml" ]; then
            echo "Invalid primary_key: ${primary_key}"
            exit 1
        fi
    fi

    # if the primary_key somehow does not exist, then exit
    if [ ! -f "${BACKUP_DIR}/${repo_dir}/${primary_key}.yaml" ]; then
        echo "Invalid primary_key: ${primary_key}"
        exit 1
    fi
    echo "${primary_key}"
}