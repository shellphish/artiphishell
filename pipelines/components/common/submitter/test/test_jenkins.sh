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

if [ ! -f aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-cp/
    pushd aixcc-sc-challenge-002-jenkins-cp
    sed -i 's/git@github.com:aixcc-sc\//http:\/\/github.com\/shellphish-support-syndicate\/aixcc-sc-/g' project.yaml
    sed -i 's/env bash/env bash\nset +e\nset -x/g' ./run.sh

    make cpsrc-prepare
    tar -cvzf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    popd
    rm -rf ./aixcc-sc-challenge-002-jenkins-cp
fi

if [ ! -f seed ]; then
    echo "AAAADQAAAAF4LWV2aWwtYmFja2Rvb3IAYnJlYWtpbiB0aGUgbGF3AGphenpl" | base64 -d > $RESOURCE_DIR/seed # Crashing Seed
fi

popd
pdl --unlock || rm -rf pipeline.lock

ipython --pdb -- `which pdl` --ignore-required

for i in $(seq 1 20);
do
    (
        echo "cp_source: plugins/pipeline-util-plugin"
        echo "crashing_commit: d4860a8ac8b8c1d4642357840adb4347f7ade43$i"
        echo "sanitizer_ids: "
        echo "    - id_1 "
        echo "crash_report_id: 3d4ee158844a08607ed066a83346b315a957acd0774ad0a433a98f6a331c841d"
        echo "crash_id: \"22$i\""
        echo "harness_id: id_1"
    ) >"$RESOURCE_DIR/commit$i.yaml"
    pd inject submitter.crashing_input_path 22$i < "$RESOURCE_DIR/seed"
    pd inject submitter.crashing_input_path 22$i < "$RESOURCE_DIR/seed"
done

pd inject submitter.crashing_input_path 223 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 224 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 225 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 226 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 227 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 228 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 229 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 230 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 231 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 232 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 233 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 234 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 235 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 236 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 237 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 238 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 239 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 240 < "$RESOURCE_DIR/seed"
pd inject submitter.crashing_input_path 241 < "$RESOURCE_DIR/seed"

pd inject submitter.crashing_commit 12345678 < "$RESOURCE_DIR/commit.yaml"
pd inject submitter.crashing_commit 12345677 < "$RESOURCE_DIR/commit2.yaml"
pd inject submitter.crashing_commit 12345676 < "$RESOURCE_DIR/commit3.yaml"
pd inject submitter.crashing_commit 12345680 < "$RESOURCE_DIR/commit5.yaml"
pd inject submitter.crashing_commit 12345681 < "$RESOURCE_DIR/commit6.yaml"
pd inject submitter.crashing_commit 12345682 < "$RESOURCE_DIR/commit7.yaml"
pd inject submitter.crashing_commit 12345683 < "$RESOURCE_DIR/commit8.yaml"
pd inject submitter.crashing_commit 12345684 < "$RESOURCE_DIR/commit9.yaml"
pd inject submitter.crashing_commit 12345685 < "$RESOURCE_DIR/commit10.yaml"
pd inject submitter.crashing_commit 12345686 < "$RESOURCE_DIR/commit11.yaml"
pd inject submitter.crashing_commit 12345687 < "$RESOURCE_DIR/commit12.yaml"
pd inject submitter.crashing_commit 12345688 < "$RESOURCE_DIR/commit13.yaml"
pd inject submitter.crashing_commit 12345689 < "$RESOURCE_DIR/commit14.yaml"
pd inject submitter.crashing_commit 12345690 < "$RESOURCE_DIR/commit15.yaml"
pd inject submitter.crashing_commit 12345691 < "$RESOURCE_DIR/commit16.yaml"
pd inject submitter.crashing_commit 12345692 < "$RESOURCE_DIR/commit17.yaml"
pd inject submitter.crashing_commit 12345693 < "$RESOURCE_DIR/commit18.yaml"
pd inject submitter.crashing_commit 12345694 < "$RESOURCE_DIR/commit19.yaml"
pd inject submitter.crashing_commit 12345695 < "$RESOURCE_DIR/commit20.yaml"

pd inject submitter.target_with_sources 1 < "$RESOURCE_DIR/aixcc-sc-challenge-002-jenkins-cp.tar.gz"
echo "time: $(date +%s)" | pd inject submitter.target_start_time 1
pd inject submitter.patch_diff 1 < "$RESOURCE_DIR/patch.diff"
#pd inject submitter_submit_gp.vds_record 234 < "$RESOURCE_DIR/vds_record.json"

pd --verbose --global-script-env "ROUND_TIME_SECONDS=200" run
pd status
