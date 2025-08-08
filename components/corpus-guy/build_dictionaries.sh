#!/bin/bash

set -eu

export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Find likely dicts for the specified format
function find_candidates() {
    format="$1"
    find /home/ruaronicola/corpus-fetch-github $SCRIPT_DIR/extra-dictionaries/ -type f \( \
      -iname "$format.dict" -o -iname "$format_fuzzer.dict" -o -iname "$format_dec_fuzzer.dict" \
    \) | sort -u
}
export -f find_candidates

function process_format() {
    format="$1"
    echo "Processing format: $format"
    
    # Create output directory
    mkdir -p "/tmp/dictionaries/$format"
    
    # Find candidate files for this format
    while read -r file; do
        # Skip if file doesn't exist or isn't readable
        [ ! -f "$file" ] || [ ! -r "$file" ] && continue
        
        # File content must be ASCII text
        if file "$file" | grep -q "ASCII text"; then
            echo "Found candidate dictionary file for $format: $file"
            hash=$(sha256sum "$file" | cut -d' ' -f1)
            cp "$file" "/tmp/dictionaries/$format/$hash"
        fi
        
    done < <(find_candidates "$format")
}
export -f process_format

# Create base directory
if [ -d /tmp/dictionaries ]; then
    read -p "The directory /tmp/dictionaries already exists. Do you want to delete it? (y/n) " answer
    if [[ $answer =~ ^[Yy]$ ]]; then
        echo "Deleting /tmp/dictionaries..."
        rm -rf /tmp/dictionaries
    fi
fi
mkdir -p /tmp/dictionaries

# Process each format
formats=$(python -c "import sys; sys.path.append('../grammar-composer'); from morpheus.magic import ALIAS_TO_NAME; print(' '.join(ALIAS_TO_NAME.keys()).lower())")
echo -n "$formats" | xargs -d ' ' -P 20 -I {} bash -c 'process_format "{}"'


##############################
# fuzzdb
echo -------------------------
echo "Processing fuzzdb"
echo -------------------------
TMPFILE=$(mktemp)
python3 $SCRIPT_DIR/unquoted_to_dict.py /home/ruaronicola/corpus-fetch-github/fuzzdb-project-fuzzdb/attack/email/*.txt > ${TMPFILE}_smtp
hash=$(sha256sum "$TMPFILE"_smtp | cut -d' ' -f1)
mv "$TMPFILE"_smtp /tmp/dictionaries/smtp/$hash
python3 $SCRIPT_DIR/unquoted_to_dict.py /home/ruaronicola/corpus-fetch-github/fuzzdb-project-fuzzdb/attack/html_js_fuzz/*.txt > ${TMPFILE}_html
hash=$(sha256sum "$TMPFILE"_html | cut -d' ' -f1)
mv "$TMPFILE"_html /tmp/dictionaries/html/$hash
python3 $SCRIPT_DIR/unquoted_to_dict.py /home/ruaronicola/corpus-fetch-github/fuzzdb-project-fuzzdb/attack/http-protocol/*.txt > ${TMPFILE}_http
hash=$(sha256sum "$TMPFILE"_http | cut -d' ' -f1)
mv "$TMPFILE"_http /tmp/dictionaries/http/$hash
python3 $SCRIPT_DIR/unquoted_to_dict.py /home/ruaronicola/corpus-fetch-github/fuzzdb-project-fuzzdb/attack/json/*.txt > ${TMPFILE}_json
hash=$(sha256sum "$TMPFILE"_json | cut -d' ' -f1)
mv "$TMPFILE"_json /tmp/dictionaries/json/$hash
python3 $SCRIPT_DIR/unquoted_to_dict.py /home/ruaronicola/corpus-fetch-github/fuzzdb-project-fuzzdb/attack/xml/*.txt > ${TMPFILE}_xml
hash=$(sha256sum "$TMPFILE"_xml | cut -d' ' -f1)
mv "$TMPFILE"_xml /tmp/dictionaries/xml/$hash


# Merge aliases into their canonical names
python -c "import sys; sys.path.append('../grammar-composer'); from morpheus.magic import ALIAS_TO_NAME; [print(f'{k} {v}'.lower()) for k,v in ALIAS_TO_NAME.items() if k != v]" | while read key value; do 
    [ -d /tmp/dictionaries/$key ] && 
    echo "Merging /tmp/dictionaries/$key into /tmp/dictionaries/$value" &&
    mkdir -p /tmp/dictionaries/$value && 
    cp -r /tmp/dictionaries/$key/* /tmp/dictionaries/$value/ 2>/dev/null && 
    rm -rf /tmp/dictionaries/$key; 
done


##############################
# merge into one normalized dictionary per format
echo -------------------------
echo "Merging into one normalized dictionary per format"
echo -------------------------
# for each format, use normalize_dictionaries.py <format> [dict1] [dict2] ... [dictN] to merge all dictionaries into one
# then output the merged dictionary to the format's directory
for format in $(ls /tmp/dictionaries); do
    echo "Merging $format"
    # save existing dictionaries
    mv /tmp/dictionaries/$format /tmp/dictionaries/$format.bak
    mkdir -p /tmp/dictionaries/$format
    # normalize
    python3 $SCRIPT_DIR/normalize_dictionaries.py /tmp/dictionaries/$format.bak/* > /tmp/dictionaries/$format/merged.dict
    # rename as sha256
    mv /tmp/dictionaries/$format/merged.dict /tmp/dictionaries/$format/$(sha256sum /tmp/dictionaries/$format/merged.dict | cut -d ' ' -f 1)
    # cleanup
    rm -rf /tmp/dictionaries/$format.bak
done

# Delete empty directories
find /tmp/dictionaries/ -type d -empty -delete

rm -rf /tmp/dictionaries.tar && tar -C /tmp/dictionaries -cf /tmp/dictionaries.tar .