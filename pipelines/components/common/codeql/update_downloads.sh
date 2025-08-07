#!/bin/bash -x

set -e
asddddddddd # ERROR, if you REALLY want this command to run, comment out this line

CODEQL_VERSION="${CODEQL_VERSION:-2.15.5}"
rm -rf ./downloads
mkdir ./downloads
cd ./downloads
wget "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"
wget "https://github.com/mikefarah/yq/releases/download/v4.43.1/yq_linux_amd64"
chmod +x yq_linux_amd64