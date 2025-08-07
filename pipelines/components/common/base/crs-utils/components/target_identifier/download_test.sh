#!/bin/bash

set -ex

rm -rf test-targets
mkdir -p test-targets/src/


REAL_TARGETS=(
    https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-cp
    https://github.com/shellphish-support-syndicate/targets-semis-clib
    https://github.com/shellphish-support-syndicate/targets-semis-apache-httpd
    https://github.com/shellphish-support-syndicate/targets-semis-harden-demo2
    https://github.com/shellphish-support-syndicate/targets-semis-linux-kernel
)
for target in "${REAL_TARGETS[@]}"; do
    git clone --depth=1 $target test-targets/src/$(basename $target)
    pushd test-targets/src/$(basename $target)
    ./run.sh pull_source
    popd
done

APT_TARGETS=(
    z3
    libyara-dev
    libyaml-dev
    libxxhash-dev
    libxslt1-dev
    libxrl-dev
    libxrandr-dev
    libxpathselect-dev
    libxmp-dev
    libxmp4
    libxml2-dev
    libxbase64-dev
)
for target in "${REAL_TARGETS[@]}"; do
    pushd test-targets/src/
    apt-get source $target
    popd
done

GIT_TARGETS=(
    https://chromium.googlesource.com/webm/libwebp
    https://github.com/pnggroup/libpng
    https://gitlab.gnome.org/GNOME/libxml2
    https://github.com/PCRE2Project/pcre2
    https://github.com/mirrorer/giflib
    https://github.com/nih-at/libzip
    https://github.com/microsoft/Z3Prover/z3
)

for target in "${GIT_TARGETS[@]}"; do
    git clone --depth=1 $target test-targets/src/$(basename $target)
done

TAR_URLS=(
    https://versaweb.dl.sourceforge.net/project/giflib/giflib-5.2.2.tar.gz
)
for target in "${TAR_URLS[@]}"; do
    wget $target -O test-targets/$(basename $target)
    OUT_DIR=$(basename $target .tar.gz)
    tar -xzf test-targets/$(basename $target) -C test-targets/src/
done
