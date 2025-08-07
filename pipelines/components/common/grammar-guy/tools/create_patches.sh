#!/bin/bash

# Do for every "submodule"
export BASEDIR="$(realpath .)"
mkdir -p "$(realpath patches/grammarinator)"
mkdir -p "$(realpath patches/mozilla_avalanche)"
sleep 1

# Patch grammarinator

if [ ! -f "$(realpath patches/grammarinator/grammarinator_full.patch)" ]; then
    touch "$(realpath patches/grammarinator/grammarinator_full.patch)"
fi

cd grammarinator
git diff > "$(realpath ../patches/grammarinator/grammarinator_full.patch)"
cd $BASEDIR


if [ ! -f "$(realpath patches/mozilla_avalanche/mozilla_avalanche_full.patch)" ]; then
    touch "$(realpath patches/mozilla_avalanche/mozilla_avalanche_full.patch)"
fi

# Patch Avalance
cd mozilla_avalanche
git diff > "$(realpath ../patches/mozilla_avalanche/mozilla_avalanche_full.patch)"
cd $BASEDIR

if [ ! -f "$(realpath patches/agentlib/agentlib_full.patch)" ]; then
    touch "$(realpath patches/agentlib/agentlib_full.patch)"
fi

cd agentlib
git diff > "$(realpath ../patches/agentlib/agentlib_full.patch)"
cd $BASEDIR
