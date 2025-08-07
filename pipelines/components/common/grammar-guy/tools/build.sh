#!/bin/bash
#
set -e
set -x

export BASEDIR="$(realpath .)"
#
# 
if [ ! -d grammarinator ]; then
    git clone https://github.com/renatahodovan/grammarinator.git grammarinator
fi

cd grammarinator
git reset --hard
git apply "$(realpath ../patches/grammarinator/grammarinator_full.patch)"
cd $BASEDIR

echo "Patches applied, state restored"