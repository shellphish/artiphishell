#!/bin/bash
#
# Generate a crs/task command by tarring up required repos and issuing crs/task spec curl

# default configs

set -e -o pipefail

SCRIPT_HOME="$PWD"
ROOT_WORK_DIR="$(mktemp -d)"
TARS_DIR="$ROOT_WORK_DIR/repo-tars"
REPO_WORK_DIR="$ROOT_WORK_DIR/work"
VERBOSE=0
BASE_REF="main"

usage() {
    echo "Usage: $0 [options]"
    echo "    -v    Enable verbose output mode"
    echo "    -c    URL to the CRS to send challenge task."
    echo "    -x    Execute the crs task challenge against the CRS URL in -c on script finish. If argument is not supplied, the curl will be written to a local file."
    echo "    -s    Directory of sarifs to inject"
    echo "    -t    Task ID to use for the challenge"
    exit 1
}

export CRS_API_KEY_ID='c0c3003b-2a83-4a52-8a76-95a0a95e710f'
export CRS_API_TOKEN='IVGVvs8slCICkUf3NhSDIW8cM0LAsLdS'

parseargs() {
    while getopts ":hvxc:s:t:" opt; do
        case $opt in
            v) VERBOSE=1 ;;
            h) usage ;;
            x) EXECUTE_CURL=1 ;;
            c) CRS_URL=$OPTARG ;;
            s) SARIF_DIR=$OPTARG ;;
            t) CRS_TASK_ID=$OPTARG ;;
            \?) echo "Invalid option: -$OPTARG"; usage ;;
            :) echo "Option -$OPTARG requires an argument"; usage ;;
        esac
    done
    if [ -z "$CRS_URL" ]; then
        echo "Ensure -c (CRS URL) is set"
        usage
    fi
    if [ -z "$SARIF_DIR" ]; then
        echo "Ensure -s (sarif directory) is set"
        usage
    fi
    if [ -z "$CRS_TASK_ID" ]; then
        echo "Ensure -t (task ID) is set"
        usage
    fi
}

getenvvars() {
    if [ -f ./.env ]; then
        source ./.env
    fi
    if [ $VERBOSE == 1 ]; then echo "Check for required environment variables"; fi
    for envvar in CRS_API_KEY_ID CRS_API_TOKEN; do
        if [ -z "${!envvar}" ]; then
            echo "Ensure $envvar variable is set."
            exit 2
        fi
    done
}

checkdeps() {
    if ! (which jq >/dev/null 2>&1); then
        echo "jq required, please install jq."
        exit 3
    fi
    if ! (which curl >/dev/null 2>&1); then
        echo "curl required, please install curl."
        exit 3
    fi
}

generatecurl(){
    local sarif_dir=$1
    local taskid=$2
    local msgid="$(uuidgen)"
    local currtime="$(($(date +%s) * 1000))"

    local broadcasts=()
    for sarif in $sarif_dir/*.sarif; do
        broadcasts+=("{\
            \"sarif_id\": \"$(uuidgen)\",\
            \"task_id\": \"$taskid\",\
            \"sarif\": $(cat $sarif),\
            \"metadata\": {}\
        }")
    done
    local payload="{ \
        \"message_id\": \"$msgid\",\
        \"message_time\": $currtime,\
        \"broadcasts\": [$(IFS=,; echo "${broadcasts[*]}")]\
    }"

    echo "$payload" | jq -c > /tmp/${msgid}.json
    CURL_CMD="curl -s -X POST \"$CRS_URL/v1/sarif/\" -H \"Content-Type: application/json\" \
        --user \"$CRS_API_KEY_ID\":\"$CRS_API_TOKEN\" -d @/tmp/${msgid}.json"
}

sendcurl(){
    echo "Execute Curl Command at $CRS_URL"
    eval "$1"
}

cleanup() {
    if [ $VERBOSE == 1 ]; then echo "Remove temp dir $ROOT_WORK_DIR"; fi
    rm -rf "$ROOT_WORK_DIR"
}

main() {
    parseargs "$@"
    getenvvars
    checkdeps

    if [ "$VERBOSE" == 1 ]; then echo "Working dir: $ROOT_WORK_DIR"; fi
    # Start doing stuff
    mkdir -p "$TARS_DIR"
    generatecurl "$SARIF_DIR" "$CRS_TASK_ID"
    if [ $VERBOSE == 1 ]; then echo "DEBUG: CURL_CMD: $CURL_CMD"; fi
    if [ "$EXECUTE_CURL" == 1 ]; then
        sendcurl "$CURL_CMD"
    else
        cd "$SCRIPT_HOME"
        if [ $VERBOSE == 1 ]; then echo "Output curl command to task_crs.sh in $SCRIPT_HOME"; fi
        echo "#!/bin/bash" > task_crs.sh
        echo "$CURL_CMD" >> task_crs.sh
        chmod +x task_crs.sh
    fi
    cleanup
}

main "$@"
