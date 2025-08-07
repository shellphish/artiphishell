:#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
HARNESS_ID=$1

echo "Injecting crashing inputs into pydatatask"

pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/0e486d83efb555166d1e3ff18d66c64f.yaml
pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/0e486d83efb555166d1e3ff18d66c64f
pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/0e486d83efb555166d1e3ff18d66c64f.yaml
pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/0e486d83efb555166d1e3ff18d66c64f.yaml
echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"
