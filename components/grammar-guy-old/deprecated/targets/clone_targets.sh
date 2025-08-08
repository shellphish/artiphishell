#!/bin/bash
#

export BASEDIR="$(realpath .)"

if [ ! -d "$(realpath target-semis-clib)" ]; then

    git clone https://github.com/shellphish-support-syndicate/targets-semis-clib.git
    cd $BASEDIR
fi

if [ ! -d "$(realpath target-semis-cjson)" ]; then

    git clone https://github.com/shellphish-support-syndicate/targets-semis-cjson.git
    cd $BASEDIR
fi

if [ ! -d "$(realpath target-semis-jq)" ]; then

    git clone https://github.com/shellphish-support-syndicate/targets-semis-jq.git
    cd $BASEDIR
fi