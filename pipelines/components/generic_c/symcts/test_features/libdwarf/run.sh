#!/bin/sh

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

get_target() {
    URL=$1
    LOCALNAME=$2
    if [ ! -d $LOCALNAME ]; then
        git clone --recursive $URL $LOCALNAME
        make cpsrc-prepare -C $LOCALNAME
    fi
    if [ ! -f $LOCALNAME.tar.gz ]; then
        tar -czf $LOCALNAME.tar.gz -C $LOCALNAME .
    fi
}

get_target https://github.com/shellphish-support-syndicate/targets-semis-libdwarf.git target-libdwarf

pdl --unlock || rm -rf pipeline.lock
ipython --pdb $(which pdl)
pd inject symcts_build_symcc.target_id 1 < ./target-libdwarf.tar.gz

# pd inject fuzz_symcts.target 2 < ../../targets/C/adams/adams-pipeline.tar.gz
# pd inject fuzz_symcts.runtime_config 2 << EOF
# env: "CHESS=1"
# args: "-s"
# EOF

pd --verbose --fail-fast --debug-trace run
pd status

set +x
