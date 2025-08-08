#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

OS=linux64
if [[ "$OSTYPE" == "darwin"* ]] ; then
  OS=osx64
fi
# TODO Add Windows support?

TMPDIR="$( mktemp -d -t 'jenkins-codeql-tests.XXX' )"
echo "Using temp dir $TMPDIR ..." >&2
cd "$TMPDIR"

echo "Downloading CodeQL CLI ..." >&2
curl --location --silent --fail --output codeql.zip "https://github.com/github/codeql-cli-binaries/releases/download/v2.15.1/codeql-${OS}.zip"

echo "Extracting CodeQL CLI ..." >&2
unzip -q codeql.zip # Into codeql/ directory

export PATH="$PATH:$PWD/codeql/"

cd - >/dev/null

echo "Downloading query pack dependencies ..." >&2
codeql pack install test/

echo "Running query tests ..." >&2
codeql test run test/

# TODO this doesn't run when tests fail, but perhaps useful for debug?
rm -rf "$TMPDIR"
