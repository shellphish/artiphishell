#!/bin/bash

set -eu

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
DICTIONARIES_DIR=$SCRIPT_DIR/dictionaries

merge_dictionary() {
    source_file="$1"
    dest_dir="$2"
    
    mkdir -p $dest_dir
    cp "$source_file" $dest_dir/$(sha256sum "$source_file" | cut -d ' ' -f 1)
}

# confirm before deleting
echo "This script will delete (and re-build) the current dictionaries dir: $DICTIONARIES_DIR"
read -p "Are you sure? (y/n) " -n 1 -r

rm -rf $DICTIONARIES_DIR
rm -rf /tmp/dictionaries
mkdir -p /tmp/dictionaries

##############################
# AFLplusplus
echo -------------------------
echo "Processing AFLplusplus"
git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /tmp/dictionaries/AFLplusplus
echo -------------------------
find /tmp/dictionaries/AFLplusplus/dictionaries/ -type f -name "*.dict" | while read file; do
    # format is filename without extension
    format=$(basename $file | cut -d '.' -f 1)
    merge_dictionary $file $DICTIONARIES_DIR/$format
done

##############################
# google-fuzzing
echo -------------------------
echo "Processing google-fuzzing"
git clone --depth 1 https://github.com/google/fuzzing.git /tmp/dictionaries/google-fuzzing
echo -------------------------
find /tmp/dictionaries/google-fuzzing/dictionaries/ -type f -name "*.dict" | while read file; do
    # format is filename without extension
    format=$(basename $file | cut -d '.' -f 1)
    merge_dictionary $file $DICTIONARIES_DIR/$format
done

##############################
# nigeltao-mozsec-fuzzdata
echo -------------------------
echo "Processing nigeltao-mozsec-fuzzdata"
git clone --depth 1 https://github.com/nigeltao/mozsec-fuzzdata.git /tmp/dictionaries/nigeltao-mozsec-fuzzdata
echo -------------------------
find /tmp/dictionaries/nigeltao-mozsec-fuzzdata/dicts/ -type f -name "*.dict" | while read file; do
    # format is filename without extension
    format=$(basename $file | cut -d '.' -f 1)
    merge_dictionary $file $DICTIONARIES_DIR/$format
done

##############################
# fuzzdb
echo -------------------------
echo "Processing fuzzdb"
git clone --depth 1 https://github.com/fuzzdb-project/fuzzdb.git /tmp/dictionaries/fuzzdb
echo -------------------------
TMPFILE=$(mktemp)
python3 $SCRIPT_DIR/unquoted_to_dict.py /tmp/dictionaries/fuzzdb/attack/email/*.txt > ${TMPFILE}_smtp
merge_dictionary ${TMPFILE}_smtp $DICTIONARIES_DIR/smtp
python3 $SCRIPT_DIR/unquoted_to_dict.py /tmp/dictionaries/fuzzdb/attack/html_js_fuzz/*.txt > ${TMPFILE}_html
merge_dictionary ${TMPFILE}_html $DICTIONARIES_DIR/html
python3 $SCRIPT_DIR/unquoted_to_dict.py /tmp/dictionaries/fuzzdb/attack/http-protocol/*.txt > ${TMPFILE}_http
merge_dictionary ${TMPFILE}_http $DICTIONARIES_DIR/http
python3 $SCRIPT_DIR/unquoted_to_dict.py /tmp/dictionaries/fuzzdb/attack/json/*.txt > ${TMPFILE}_json
merge_dictionary ${TMPFILE}_json $DICTIONARIES_DIR/json
python3 $SCRIPT_DIR/unquoted_to_dict.py /tmp/dictionaries/fuzzdb/attack/xml/*.txt > ${TMPFILE}_xml
merge_dictionary ${TMPFILE}_xml $DICTIONARIES_DIR/xml
# TODO: maybe include unicode dict (unicode)
# TODO: maybe include command injection dict (os-cmd-execution)
# TODO: maybe include path traversal dict (path-traversal)
# TODO: maybe include sql injection dict (sql-injection)
# TODO: maybe include ldap injection dict (ldap)

##############################
# Custom dictionaries
echo -------------------------
echo "Processing custom dictionaries"
echo -------------------------
merge_dictionary extra-dictionaries/http.dict $DICTIONARIES_DIR/http
merge_dictionary extra-dictionaries/smtp.dict $DICTIONARIES_DIR/smtp
merge_dictionary extra-dictionaries/wast.dict $DICTIONARIES_DIR/wasm
merge_dictionary extra-dictionaries/wast.dict $DICTIONARIES_DIR/wast

##############################
# merge variants
echo -------------------------
echo "Merging variants"
echo -------------------------
groups=(
    "html html_tags"
    "netpbm pbm"
)

for group in "${groups[@]}"; do
    group=($group)
    mkdir -p $DICTIONARIES_DIR/${group[0]}
    for format in "${group[@]:1}"; do
        echo "Merging $format into ${group[0]}"
        mv $DICTIONARIES_DIR/$format/* $DICTIONARIES_DIR/${group[0]}
        rm -rf $DICTIONARIES_DIR/$format
    done
done

##############################
# delete formats that don't have a corresponding entry in corpus/
echo -------------------------
echo "Deleting formats without a corresponding entry in corpus/"
echo -------------------------
for format in $(ls $DICTIONARIES_DIR); do
    if [ ! -d $SCRIPT_DIR/corpus/$format ]; then
        # echo "Deleting $format"
        rm -rf $DICTIONARIES_DIR/$format
    fi
done

##############################
# merge into one normalized dictionary per format
echo -------------------------
echo "Merging into one normalized dictionary per format"
echo -------------------------
# for each format, use normalize_dictionaries.py <format> [dict1] [dict2] ... [dictN] to merge all dictionaries into one
# then output the merged dictionary to the format's directory
for format in $(ls $DICTIONARIES_DIR); do
    echo "Merging $format"
    # save existing dictionaries
    mv $DICTIONARIES_DIR/$format $DICTIONARIES_DIR/$format.bak
    mkdir -p $DICTIONARIES_DIR/$format
    # normalize
    python3 $SCRIPT_DIR/normalize_dictionaries.py $DICTIONARIES_DIR/$format.bak/* > $DICTIONARIES_DIR/$format/merged.dict
    # rename as sha256
    mv $DICTIONARIES_DIR/$format/merged.dict $DICTIONARIES_DIR/$format/$(sha256sum $DICTIONARIES_DIR/$format/merged.dict | cut -d ' ' -f 1)
    # cleanup
    rm -rf $DICTIONARIES_DIR/$format.bak
done
