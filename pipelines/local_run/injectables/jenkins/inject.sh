#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Injecting crashing inputs into pydatatask"

pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604be5.yaml
pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604be5
pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604be5.yaml
pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604be5.yaml
echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"