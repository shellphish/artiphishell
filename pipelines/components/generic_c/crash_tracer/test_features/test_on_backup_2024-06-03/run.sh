#!/bin/bash

# set -e
# set -x

BACKUP_DIR="$(realpath ./backup)"

TEMPDIR=$(mktemp -d)
ANY_FAILED=0
for f in "$BACKUP_DIR"/asan2report.representative_crash_metadata/*; do
    python ../../asan2report.py "$f" "$TEMPDIR/$(basename $f)" > /dev/null 2>&1
    SUCCESS=$?
    if [ $SUCCESS -ne 0 ]; then
        echo "$f: failed"
        ANY_FAILED=1
    else
        echo "$f: success"
    fi
done

function assert_eq() {
    if [ "$1" != "$2" ]; then
        echo "assertion failed: $1 != $2"
        exit 1
    fi
}
function check_report() {
    report_path="$1"
    report_name=$(basename "$report_path")


    # 7c4699dcd770c3b420ac25ca40ee6afedcfee62d321288344cd475fff8429892.yaml
    set -x
    if [ "$report_name" == "7c4699dcd770c3b420ac25ca40ee6afedcfee62d321288344cd475fff8429892.yaml" ]; then
        # first, get the stack traces, make sure the main stacktrace has 9 entries
        assert_eq 9 "$(yq '.stack_traces.main | length' "$report_path")"
        assert_eq "read" "$(yq '.crash_action.access' "$report_path")"
        assert_eq 3 "$(yq '.crash_action.size' "$report_path")"
        assert_eq "global-buffer-overflow" "$(yq '.crash_type' "$report_path")"
        assert_eq "AddressSanitizer: global-buffer-overflow" "$(yq '.sanitizer' "$report_path")"
    fi
    set +x
}

echo "Generated reports: $TEMPDIR"
for f in "$TEMPDIR"/*; do
    check_report "$f"
done
if [ $ANY_FAILED -ne 0 ]; then
    exit 1
fi
