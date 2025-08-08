#!/bin/bash

set -e
set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CORPUS_DIR_UNFILTERED=$SCRIPT_DIR/corpus-unfiltered
CORPUS_DIR_FILTERED=$SCRIPT_DIR/corpus-filtered

filter_best_seeds() {
  local dir="$1"
  
  # List immediate files in the directory.
  mapfile -t files < <(find "$dir" -maxdepth 1 -type f)
  [ ${#files[@]} -eq 0 ] && return
  
  # Build mapping: file -> MIME type, and count occurrences.
  declare -A file_mime mime_count
  for f in "${files[@]}"; do
    local m
    m=$(file -b --mime-type "$f")
    file_mime["$f"]="$m"
    (( mime_count["$m"] = ${mime_count["$m"]:-0} + 1 ))
  done
  
  # Determine the majority MIME type.
  local majority="" max=0
  for m in "${!mime_count[@]}"; do
    (( mime_count["$m"] > max )) && { majority="$m"; max=${mime_count["$m"]}; }
  done
  
  # Collect files with the majority MIME type.
  local maj_files=()
  for f in "${!file_mime[@]}"; do
    [[ "${file_mime[$f]}" == "$majority" ]] && maj_files+=( "$f" )
  done
  
  # Select seeds: take up to 50 from the majority group, then fill with others.
  local selected=()
  if (( ${#maj_files[@]} >= 50 )); then
    selected=( $(printf "%s\n" "${maj_files[@]}" | shuf | head -n 50) )
  else
    selected=( "${maj_files[@]}" )
    local needed=$((50 - ${#selected[@]}))
    local others=()
    for f in "${!file_mime[@]}"; do
      [[ "${file_mime[$f]}" != "$majority" ]] && others+=( "$f" )
    done
    selected+=( $(printf "%s\n" "${others[@]}" | shuf | head -n "$needed") )
  fi
  
  # Delete files that are not among the selected seeds.
  for f in "${files[@]}"; do
    if ! printf "%s\n" "${selected[@]}" | grep -Fxq "$f"; then
      rm "$f"
    fi
  done
}

merge_corpus_filtered() {
    corpus_source_dir="$1"
    corpus_dest_dir="$2"
    
    mkdir -p $corpus_dest_dir
    # handle filenames with spaces
    # NOTE: attempt to curate a little bit by excluding automatically generated files
    find $corpus_source_dir -type f -regextype posix-extended \
         ! -regex '.*/[0-9a-f]{32}\..*' \
         ! -regex '.*/([0-9a-f]{40}(-[0-9]+)?|id[_:][0-9]{6}.*)$' \
         -print0 \
         | while IFS= read -r -d $'\0' file; do
        cp "$file" $corpus_dest_dir/$(sha256sum "$file" | cut -d ' ' -f 1)
    done
}

merge_corpus_unfiltered() {
    corpus_source_dir="$1"
    corpus_dest_dir="$2"
    
    mkdir -p $corpus_dest_dir
    # handle filenames with spaces
    find $corpus_source_dir -type f -print0 | while IFS= read -r -d $'\0' file; do
        cp "$file" $corpus_dest_dir/$(sha256sum "$file" | cut -d ' ' -f 1)
    done
}

# confirm before deleting
echo "This script will delete (and re-build) the current corpus dirs: $CORPUS_DIR_FILTERED $CORPUS_DIR_UNFILTERED"
read -p "Are you sure? (y/n) " -n 1 -r

rm -rf $CORPUS_DIR_FILTERED
rm -rf $CORPUS_DIR_UNFILTERED
rm -rf /tmp/corpus
mkdir -p /tmp/corpus

##############################
# AFLplusplus
echo -------------------------
echo "Processing AFLplusplus"
git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /tmp/corpus/AFLplusplus
echo -------------------------
find /tmp/dictionaries/AFLplusplus/testcases/ -type d -links 2 | while read path; do
    # format is directory name
    format=$(basename $path)
    merge_corpus_filtered $path $CORPUS_DIR_FILTERED/$format
    merge_corpus_unfiltered $path $CORPUS_DIR_UNFILTERED/$format
done

# TODO: some of the seeds in go-fuzz-corpus are pretty bad (e.g., http, smtp)
# how can we curate the corpus without minimizing much?
##############################
# go-fuzz-corpus
echo -------------------------
echo "Processing go-fuzz-corpus"
git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus /tmp/corpus/go-fuzz-corpus
rm -rf /tmp/corpus/go-fuzz-corpus/.git
# remove/rename some dirs
rm -rf /tmp/corpus/go-fuzz-corpus/testcover
mv /tmp/corpus/go-fuzz-corpus/smtp /tmp/corpus/go-fuzz-corpus/smtpresp
mv /tmp/corpus/go-fuzz-corpus/parser /tmp/corpus/go-fuzz-corpus/sqlparser
echo -------------------------
# corpuses are in <format>/**/*corpus*/
# find all format dirs
find /tmp/corpus/go-fuzz-corpus -mindepth 1 -maxdepth 1 -type d | while read -r format_dir; do
    format=$(basename $format_dir)
    echo "Processing go-fuzz-corpus/$format"
    
    # find all corpus dirs
    find $format_dir -type d -name "*corpus*" | while read -r corpus_dir; do
        merge_corpus_filtered $corpus_dir $CORPUS_DIR_FILTERED/$format
        merge_corpus_unfiltered $corpus_dir $CORPUS_DIR_UNFILTERED/$format
    done
done

##############################
# fuzzing-corpus
echo -------------------------
echo "Processing fuzzing-corpus"
git clone --depth 1 https://github.com/strongcourage/fuzzing-corpus /tmp/corpus/fuzzing-corpus
rm -rf /tmp/corpus/fuzzing-corpus/dictionaries /tmp/corpus/fuzzing-corpus/.git
echo -------------------------
# corpuses are in <format>/
find /tmp/corpus/fuzzing-corpus -mindepth 1 -maxdepth 1 -type d | while read -r format_dir; do
    format=$(basename $format_dir)
    echo "Processing fuzzing-corpus/$format"
    merge_corpus_filtered $format_dir $CORPUS_DIR_FILTERED/$format
    merge_corpus_unfiltered $format_dir $CORPUS_DIR_UNFILTERED/$format
done

##############################
# lwan (http)
echo -------------------------
echo "Processing lwan (http)"
git clone --depth 1 https://github.com/lpereira/lwan /tmp/corpus/lwan
rm -rf /tmp/corpus/lwan/.git /tmp/corpus/lwan/fuzz/*/README
# remove/rename some dirs
find /tmp/corpus/lwan -type f -name "*config*" -delete
find /tmp/corpus/lwan -type f -name "*pattern*" -delete
find /tmp/corpus/lwan -type f -name "*huffman*" -delete
find /tmp/corpus/lwan -type f -name "*template*" -delete
echo -------------------------
# corpuses are in fuzz/corpus fuzz/disabled fuzz/regression
for corpus_dir in fuzz/corpus fuzz/disabled fuzz/regression; do
    merge_corpus_filtered /tmp/corpus/lwan/$corpus_dir $CORPUS_DIR_FILTERED/http
    merge_corpus_unfiltered /tmp/corpus/lwan/$corpus_dir $CORPUS_DIR_UNFILTERED/http
done

##############################
# curl (smtp)
echo -------------------------
echo "Processing curl (smtp)"
git clone --depth 1 https://github.com/curl/curl /tmp/corpus/curl
rm -rf /tmp/corpus/curl/.git
echo -------------------------
# smtp tests are in tests/data
mkdir /tmp/corpus/curl-smtp
for test in $(find /tmp/corpus/curl/tests/data -type f -name "test*"); do
    id=$(basename $test)
    sed -n '/<keywords>/,/<\/keywords>/ {//!p}' $test | grep -q SMTP && sed -n '/<protocol>/,/<\/protocol>/ {//!p}' $test > /tmp/corpus/curl-smtp/$id
done
merge_corpus_filtered /tmp/corpus/curl-smtp $CORPUS_DIR_FILTERED/smtp
merge_corpus_unfiltered /tmp/corpus/curl-smtp $CORPUS_DIR_UNFILTERED/smtp

mkdir /tmp/corpus/curl-http
for test in $(find /tmp/corpus/curl/tests/data -type f -name "test*"); do
    id=$(basename $test)
    sed -n '/<keywords>/,/<\/keywords>/ {//!p}' $test | grep -q HTTP && sed -n '/<protocol>/,/<\/protocol>/ {//!p}' $test > /tmp/corpus/curl-http/$id
done
merge_corpus_filtered /tmp/corpus/curl-http $CORPUS_DIR_FILTERED/http
merge_corpus_unfiltered /tmp/corpus/curl-http $CORPUS_DIR_UNFILTERED/http

##############################
# libpng (png)
echo -------------------------
echo "Processing libpng (png)"
git clone --depth 1 https://github.com/lunapaint/pngsuite.git /tmp/corpus/pngsuite
echo -------------------------
merge_corpus_filtered /tmp/corpus/pngsuite/png $CORPUS_DIR_FILTERED/png
merge_corpus_unfiltered /tmp/corpus/pngsuite/png $CORPUS_DIR_UNFILTERED/png

##############################
# wasm_runtimes_fuzzing (wasm)
echo -------------------------
echo "Processing wasm_runtimes_fuzzing (wasm)"
git clone --depth 1 https://github.com/FuzzingLabs/wasm_runtimes_fuzzing.git /tmp/corpus/wasm_runtimes_fuzzing
echo -------------------------
merge_corpus_filtered /tmp/corpus/wasm_runtimes_fuzzing/trophies $CORPUS_DIR_FILTERED/wasm
merge_corpus_unfiltered /tmp/corpus/wasm_runtimes_fuzzing/trophies $CORPUS_DIR_UNFILTERED/wasm

##############################
# wasm-fuzz (wasm)
echo -------------------------
echo "Processing wasm-fuzz (wasm)"
git clone --depth 1 https://github.com/wasmerio/wasm-fuzz.git /tmp/corpus/wasm-fuzz
echo -------------------------
merge_corpus_filtered /tmp/corpus/wasm-fuzz/crashes $CORPUS_DIR_FILTERED/wasm
merge_corpus_unfiltered /tmp/corpus/wasm-fuzz/crashes $CORPUS_DIR_UNFILTERED/wasm

# https://github.com/wasm3/wasm3.git
##############################
# wasm3 (wasm)
echo -------------------------
echo "Processing wasm3 (wasm)"
git clone --depth 1 https://github.com/wasm3/wasm3.git /tmp/corpus/wasm3
echo -------------------------
# copy all .wasm files in /tmp/corpus/wasm3/test/ to /tmp/corpus/wasm3/corpus
mkdir -p /tmp/corpus/wasm3/corpus
find /tmp/corpus/wasm3/test -type f -name "*.wasm" -exec cp {} /tmp/corpus/wasm3/corpus \;
merge_corpus_filtered /tmp/corpus/wasm3/corpus $CORPUS_DIR_FILTERED/wasm
merge_corpus_unfiltered /tmp/corpus/wasm3/corpus $CORPUS_DIR_UNFILTERED/wasm

# ##############################
# # JavaClass Corpus (Apache Commons Lang)
# echo -------------------------
# echo "Processing JavaClass Corpus (Apache Commons Lang)"
# mkdir -p /tmp/corpus/javaclass/corpus
# curl -L -o /tmp/corpus/javaclass/commons-lang3.jar https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
# mkdir -p /tmp/corpus/javaclass/temp
# cd /tmp/corpus/javaclass/temp
# jar xf ../commons-lang3.jar
# find . -type f -name "*.class" -exec cp {} /tmp/corpus/javaclass/corpus \;
# merge_corpus_filtered /tmp/corpus/javaclass/corpus $CORPUS_DIR_FILTERED/javaclass
# merge_corpus_unfiltered /tmp/corpus/javaclass/corpus $CORPUS_DIR_UNFILTERED/javaclass


##############################
# merge variants
echo -------------------------
echo "Merging variants"
echo -------------------------
groups=(
    "m4a m4a-aac"
    "bz2 bzip2"
    "deflate flate zlib"
    "gz gzip"
    "html htmltemplate stdhtml"
    "http httpreq"
    "httpresp httpresp"
    "jpeg jpg"
    "jpeg2000 j2k jp2 jpc"
    "mpegaudio mp1 mp2 mp3"
    "netpbm pbm pgm ppm pnm"
    "ogg ogv"
    "pcap gopacket"
    "ruby rb"
    "sql sqlparser"
    "tls tlsclient"
    "ttf freetype truetype"
    "websocket websocketclient websocketserver"
    "x509 pem crt"
)

for group in "${groups[@]}"; do
    group=($group)
    for format in "${group[@]:1}"; do
        echo "Merging $format into ${group[0]}"
        mkdir -p $CORPUS_DIR_FILTERED/${group[0]}
        mkdir -p $CORPUS_DIR_UNFILTERED/${group[0]}
        mv $CORPUS_DIR_FILTERED/$format/* $CORPUS_DIR_FILTERED/${group[0]} &> /dev/null || true
        mv $CORPUS_DIR_UNFILTERED/$format/* $CORPUS_DIR_UNFILTERED/${group[0]} &> /dev/null || true
        rm -rf $CORPUS_DIR_FILTERED/$format
        rm -rf $CORPUS_DIR_UNFILTERED/$format
    done
done

##############################
# filter
echo -------------------------
echo "Filtering"
echo -------------------------
# remove empty files
find $CORPUS_DIR_FILTERED -type f ! -exec grep -q '[^[:space:]]' {} \; -delete
find $CORPUS_DIR_UNFILTERED -type f ! -exec grep -q '[^[:space:]]' {} \; -delete

# remove dirs with less than 10 files
find "$CORPUS_DIR_FILTERED" -mindepth 1 -depth -type d -exec bash -c '[[ $(find "$1" -type f | wc -l) -lt 10 ]] && rm -rf "$1"' _ {} \;
find "$CORPUS_DIR_UNFILTERED" -mindepth 1 -depth -type d -exec bash -c '[[ $(find "$1" -type f | wc -l) -lt 10 ]] && rm -rf "$1"' _ {} \;

# EXTRA FILTERING FOR FILTERED CORPUS
# remove large files
find $CORPUS_DIR_FILTERED -type f -size +100k -delete
# keep at most 50 files per dir
find $CORPUS_DIR_FILTERED -mindepth 1 -type d | while read -r dir; do
    # find $dir -maxdepth 1 -type f -print0 | shuf -z | tail -zn +51 | xargs -0 rm &> /dev/null || true
    echo "Filtering $dir"
    filter_best_seeds $dir
done

# remove dirs with less than 10 files
find "$CORPUS_DIR_FILTERED" -mindepth 1 -depth -type d -exec bash -c '[[ $(find "$1" -type f | wc -l) -lt 10 ]] && rm -rf "$1"' _ {} \;
find "$CORPUS_DIR_UNFILTERED" -mindepth 1 -depth -type d -exec bash -c '[[ $(find "$1" -type f | wc -l) -lt 10 ]] && rm -rf "$1"' _ {} \;

# remove unmatched corpus-unfiltered dirs
find "$CORPUS_DIR_UNFILTERED" -mindepth 1 -depth -type d | while read -r dir; do
    base=$(basename $dir)
    if [ ! -d "$CORPUS_DIR_FILTERED/$base" ]; then
        echo "Removing unmatched unfiltered dir $dir"
        rm -rf $dir
    fi
done

# remove all dirs in the unfiltered corpus except for http and smtp
# find $CORPUS_DIR_UNFILTERED -mindepth 1 -maxdepth 1 -type d ! -name http ! -name smtp -exec rm -rf {} \;

##############################
# compress both corpuses
echo -------------------------
echo "Compressing both corpuses"
echo -------------------------
tar -C $CORPUS_DIR_FILTERED -czf $CORPUS_DIR_FILTERED.tar .
tar -C $CORPUS_DIR_UNFILTERED -czf $CORPUS_DIR_UNFILTERED.tar .
