::#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Injecting crashing inputs into pydatatask"

pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/75651ed9b168b9ac49636241df0ca65c.yaml
pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/75651ed9b168b9ac49636241df0ca65c
pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/75651ed9b168b9ac49636241df0ca65c.yaml
pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/75651ed9b168b9ac49636241df0ca65c.yaml
echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"
