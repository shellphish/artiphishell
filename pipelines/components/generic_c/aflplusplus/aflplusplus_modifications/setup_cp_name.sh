#!/bin/bash

export CP_NAME=$(yq '.cp_name' "$TARGET_DIR"/project.yaml | sed 's/"//g' | sed 's/[^a-zA-Z0-9]/_/g' | tr '[:upper:]' '[:lower:]')