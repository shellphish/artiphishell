#!/bin/bash

download_corpus() {
    PROJECTNAME=$1
    TARGETNAME=$2
    OUTDIR="./corpus_oss_fuzz/${PROJECTNAME}/"
    OUTPATH="$OUTDIR/${TARGETNAME}.zip"
    URL="https://storage.googleapis.com/${PROJECTNAME}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/${PROJECTNAME}_${TARGETNAME}/public.zip"
    mkdir -p "$OUTDIR"
    wget -O "${OUTPATH}" "${URL}"
    pushd "$OUTDIR"
    unar "${TARGETNAME}.zip"
    popd
}

# download_corpus "libpng" "libpng_read_fuzzer"
download_corpus "stb" "stbi_read_fuzzer"
# download_corpus "libtiff" "tiff_read_rgba_fuzzer"
# download_corpus "libtiff" "tiffcp"
