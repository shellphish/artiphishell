#!/bin/bash

set -xe

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

(
    pushd "$SCRIPT_DIR/dedup/exhibition2"
    rm -rf clusterfuzz
    rm -rf venv
    git clone https://github.com/google/clusterfuzz.git \
        && git -C clusterfuzz checkout $(cat clusterfuzz-commit-hash) \
        && python3.11 -m venv venv \
        && . venv/bin/activate \
        && python -m pip install -r requirements.txt \
        && python -m pip install -e ../../../crs-utils
    popd
)
