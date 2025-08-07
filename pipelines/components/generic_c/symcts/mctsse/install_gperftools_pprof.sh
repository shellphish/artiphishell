#!/bin/bash

set -euo pipefail
sudo apt-get install -y libtool autoconf golang-go build-essential
cd repos
git clone https://github.com/gperftools/gperftools
cd gperftools
git checkout gperftools-2.9.1
./autogen.sh
./configure
make -j

echo "Installing pprof"
go get -u github.com/google/pprof
