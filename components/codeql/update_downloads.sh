#!/bin/bash -x

set -e

CODEQL_VERSION="${CODEQL_VERSION:-2.15.5}"
TARGET_DIR="${TARGET_DIR:-./downloads}"
rm -rf ${TARGET_DIR}
mkdir ${TARGET_DIR}
cd ${TARGET_DIR}
wget "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"
wget "https://github.com/mikefarah/yq/releases/download/v4.43.1/yq_linux_amd64"
chmod +x yq_linux_amd64
