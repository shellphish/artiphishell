::#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Injecting crashing inputs into pydatatask"

pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/4dd07d5cbda20848895600e567117110.yaml
pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/4dd07d5cbda20848895600e567117110
pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/4dd07d5cbda20848895600e567117110.yaml
pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/4dd07d5cbda20848895600e567117110.yaml
echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"
