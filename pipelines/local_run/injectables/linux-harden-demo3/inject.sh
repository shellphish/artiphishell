:#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
HARNESS_ID=$1

echo "Injecting crashing inputs into pydatatask"

# implement switch case for different harnesses
if [ $HARNESS_ID == "1" ]; then
    pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/stuff-1.yaml
    pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/id_1.poc
    pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/stuff-1.yaml
    pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/stuff-1.yaml
elif [ $HARNESS_ID == "2" ]; then
    pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/stuff-2.yaml
    pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/id_2.poc
    pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/stuff-2.yaml
    pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/stuff-2.yaml
elif [ $HARNESS_ID == "3" ]; then
    pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/stuff-3.yaml
    pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/id_3.poc
    pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/stuff-3.yaml
    pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/stuff-3.yaml
elif [ $HARNESS_ID == "4" ]; then
    pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/stuff-4.yaml
    pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/id_4.poc
    pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/stuff-4.yaml
    pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/stuff-4.yaml
else
    echo "Invalid harness id"
    exit 1
fi

echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"

