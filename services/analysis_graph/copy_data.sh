#!/bin/bash
set -x

TAR=$1
NEO_DIR=$2

DEST=/tmp/analysis_graph

DIRS=(
    "data"
    "import"
    #"logs"
    "plugin"
    )

mkdir -p $DEST
tar -xvzf $TAR -C $DEST

sudo chown -R $USER:$USER $NEO_DIR

for i in ${DIRS[@]}; do
    if [ -d $DEST/analysisgraph/var/lib/neo4j/$i ];
    then
        mkdir -p $NEO_DIR/$i
        sudo rm -rf $NEO_DIR/$i/*
        cp -r $DEST/analysisgraph/var/lib/neo4j/$i/* $NEO_DIR/$i/
    fi
done

rm -rf $DEST
