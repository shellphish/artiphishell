#!/bin/bash

set -eu

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CORPUS_DIR=$SCRIPT_DIR

merge_corpus() {
    corpus_dir=$(realpath $1/seeds)
    meta_dir=$(realpath $1/meta)
    corpus_source="$2"
    corpus_source_dir="$3"
    in_dir_relative_to_source="$4"
    in_dir="$corpus_source_dir/$in_dir_relative_to_source"
    
    mkdir -p $corpus_dir $meta_dir
    for file in $(find $in_dir -type f); do
        cp $file $corpus_dir/$(sha256sum $file | cut -d ' ' -f 1)
        cat <<EOF > $meta_dir/$(sha256sum $file | cut -d ' ' -f 1).yaml
filename: $(basename $file)
sha256: $(sha256sum $file | cut -d ' ' -f 1)
source: $corpus_source
source_relative_path: $(realpath --relative-to=$corpus_source_dir $file)
EOF
    done
}

rm -rf .lwan .go-fuzz-corpus .oss-fuzz-nginx .oss-fuzz-nginx.zip
git clone https://github.com/lpereira/lwan/ .lwan
git clone https://github.com/dvyukov/go-fuzz-corpus/ .go-fuzz-corpus
wget https://storage.googleapis.com/nginx-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nginx_http_request_fuzzer/public.zip -O .oss-fuzz-nginx.zip
unzip .oss-fuzz-nginx.zip -d .oss-fuzz-nginx
python ./fix-nginx-corpus.py .oss-fuzz-nginx .oss-fuzz-nginx-requests .oss-fuzz-nginx-responses
merge_corpus $CORPUS_DIR https://test.com .custom ./
merge_corpus $CORPUS_DIR https://storage.googleapis.com/nginx-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nginx_http_request_fuzzer/public.zip .oss-fuzz-nginx ./
merge_corpus $CORPUS_DIR https://storage.googleapis.com/nginx-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nginx_http_request_fuzzer/public.zip .oss-fuzz-nginx-requests ./
merge_corpus $CORPUS_DIR https://storage.googleapis.com/nginx-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nginx_http_request_fuzzer/public.zip .oss-fuzz-nginx-responses ./
merge_corpus $CORPUS_DIR https://github.com/lpereira/lwan .lwan fuzz/corpus
merge_corpus $CORPUS_DIR https://github.com/dvyukov/go-fuzz-corpus/ .go-fuzz-corpus http2/corpus/
merge_corpus $CORPUS_DIR https://github.com/dvyukov/go-fuzz-corpus/ .go-fuzz-corpus httpreq/corpus/
merge_corpus $CORPUS_DIR https://github.com/dvyukov/go-fuzz-corpus/ .go-fuzz-corpus httpresp/corpus/