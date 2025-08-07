#!/usr/bin/bash

set -e
set -x

CUR_DIR=$(dirname $(realpath $0))
PARENT=$(realpath "$CUR_DIR/../")
pushd $PARENT
docker build \
    --build-arg "USER=00000000-0000-0000-0000-000000000000" \
    --build-arg "SECRET=secret" \
    --build-arg "LOCATION=http://172.17.0.1:8082" \
    -t aixcc-submitter .
popd

RESOURCE_DIR=$CUR_DIR/resources
pushd $RESOURCE_DIR

TARGET=targets-semis-aixcc-sc-mock-cp
if [ ! -f $TARGET.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/$TARGET
    pushd aixcc-sc-mock-cp
    make cpsrc-prepare
    tar -cvzf ../$TARGET.tar.gz .
    popd
    rm -rf ./$TARGET
fi


if [ ! -d $RESOURCE_DIR/ranking_backup ];
then
    unar $RESOURCE_DIR/ranking_backup.tar.gz
fi
popd

pushd $CUR_DIR

pdl --unlock || rm -rf pipeline.lock
ipython --pdb -- `which pdl` --ignore-required --name SUBMITTER


echo "time: $(date +%s)" | pd inject submitter.target_start_time 1
pd inject submitter.target_with_sources 1 < $RESOURCE_DIR/$TARGET.tar.gz
pd restore $RESOURCE_DIR/ranking_backup --all

for commit in $(find $RESOURCE_DIR/ranking_backup/patchery.crashing_commit -type f );
do 
    base_name=$(basename $commit)
    pd inject submitter.crashing_commit ${base_name%.*} < $commit
done
for crash in $(find $RESOURCE_DIR/ranking_backup/patchery.crashing_input_id -type f );
do 
    pd inject submitter.crashing_input_path $(basename $crash) < $crash
done

LITELLM_KEY=${LITELLM_KEY:-sk-artiphishell}
AIXCC_LITELLM_HOSTNAME=${AIXCC_LITELLM_HOSTNAME:-http://beatty.unfiltered.seclab.cs.ucsb.edu:4000/}
ipython --pdb -m pydatatask.cli.main -- $EXTRA_ENV --global-script-env "AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME" \
                                                   --global-script-env "DISABLE_GP_TIMEOUT=0"  \
                                                   --global-script-env "DISABLE_VDS_TIMEOUT=1" \
                                                   --global-script-env "ROUND_TIME_SECONDS=0" \
                                                   --global-script-env "RETRIEVAL_API=$RETRIEVAL_API" \
                                                   --global-script-env "EMBEDDING_API=$EMBEDDING_API" \
                                                   --global-script-env "LITELLM_KEY=$LITELLM_KEY" \
                                                   --verbose --debug-trace run --forever

if [ ! -f /tmp/pdt_magic ]; then
    kill -INT $AGENT_PID
fi
wait
popd

pd status

popd