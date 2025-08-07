#!/bin/bash

OUTDIR=./pkgs
mkdir -p ${OUTDIR}
cd ${OUTDIR}

PACKAGES="clang-14"
apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances \
  --no-pre-depends ${PACKAGES} | grep "^\w")
