#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Injecting crashing inputs into pydatatask"

pd inject povguy.crashing_input_id 1 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604be3.yaml
pd inject povguy.crashing_input_path 1 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604be3
pd inject povguy.crashing_input_metadata 1 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604be3.yaml
pd inject povguy.crashing_input_metadata_path 1 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604be3.yaml

pd inject povguy.crashing_input_id 2 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604be6.yaml
pd inject povguy.crashing_input_path 2 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604be6
pd inject povguy.crashing_input_metadata 2 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604be6.yaml
pd inject povguy.crashing_input_metadata_path 2 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604be6.yaml


pd inject povguy.crashing_input_id 3 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604be8.yaml
pd inject povguy.crashing_input_path 3 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604be8
pd inject povguy.crashing_input_metadata 3 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604be8.yaml
pd inject povguy.crashing_input_metadata_path 3 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604be8.yaml


pd inject povguy.crashing_input_id 4 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604be9.yaml
pd inject povguy.crashing_input_path 4 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604be9
pd inject povguy.crashing_input_metadata 4 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604be9.yaml
pd inject povguy.crashing_input_metadata_path 4 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604be9.yaml


pd inject povguy.crashing_input_id 5 < $SCRIPT_DIR/povguy.crashing_input_id/03fb77b106efa81347f5b3fdae604beb.yaml
pd inject povguy.crashing_input_path 5 < $SCRIPT_DIR/povguy.crashing_input_path/03fb77b106efa81347f5b3fdae604beb
pd inject povguy.crashing_input_metadata 5 < $SCRIPT_DIR/povguy.crashing_input_metadata/03fb77b106efa81347f5b3fdae604beb.yaml
pd inject povguy.crashing_input_metadata_path 5 < $SCRIPT_DIR/povguy.crashing_input_metadata_path/03fb77b106efa81347f5b3fdae604beb.yaml