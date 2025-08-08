#!/bin/bash
set -eux

# Add the github token from .git-credentials to the scantron.yaml file

SERVER_DIR=$(realpath $(dirname $0))
# Split on : and take everything until the @
GITHUB_TOKEN=${GITHUB_TOKEN:-$(head -n 1 ~/.git-credentials)}
GH_USER=$(echo $GITHUB_TOKEN | cut -d: -f2 | cut -d/ -f3)
GH_PAT=$(echo $GITHUB_TOKEN | cut -d: -f3 | cut -d@ -f1)

ARTIPHISHELL_API_USERNAME=${ARTIPHISHELL_API_USERNAME:-"shellphish"}
ARTIPHISHELL_API_PASSWORD=${ARTIPHISHELL_API_PASSWORD:-"!!!shellphish!!!"}
ARTIPHISHELL_API_URL=${ARTIPHISHELL_API_URL:-"http://localhost:8000"}

COMPETITION_SERVER_API_ID=${COMPETITION_SERVER_API_ID:-"11111111-1111-1111-1111-111111111111"}
COMPETITION_SERVER_API_KEY=${COMPETITION_SERVER_API_KEY:-"secret"}

# Run the server
pushd $SERVER_DIR
  cp scantron.template.yaml scantron.yaml
  yq eval ".github.pat = \"$GH_PAT\"" -i scantron.yaml
  yq eval ".teams[0].crs.api_key_id = \"$ARTIPHISHELL_API_USERNAME\"" -i scantron.yaml
  yq eval ".teams[0].crs.api_key_token = \"$ARTIPHISHELL_API_PASSWORD\"" -i scantron.yaml
  yq eval ".teams[0].crs.url = \"$ARTIPHISHELL_API_URL\"" -i scantron.yaml
  yq eval ".teams[0].id = \"$COMPETITION_SERVER_API_ID\"" -i scantron.yaml
  yq eval ".teams[0].api_key.token = \"$COMPETITION_SERVER_API_KEY\"" -i scantron.yaml
popd