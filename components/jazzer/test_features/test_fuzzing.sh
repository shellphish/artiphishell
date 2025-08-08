#! /bin/bash

set -e
set -x

CUR_DIR=$(dirname $(realpath $0))
cd $CUR_DIR/fuzz_jenkins

if [ ! -f aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-cp/
    pushd aixcc-sc-challenge-002-jenkins-cp
    sed -i 's/git@github.com:aixcc-sc\//http:\/\/github.com\/shellphish-support-syndicate\/aixcc-sc-/g' .env.project
    #sed -i 's/ghcr.io\/aixcc-sc\/challenge-002-jenkins-cp:v1.0.0/aixcc-jenkins-jazzer-harness/g' .env.project
    sed -i 's/env bash/env bash\nset +e\nset -x/g' ./run.sh
    make cpsrc-prepare
    #./run.sh pull_source
    tar -cvzf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    popd
    rm -rf ./aixcc-sc-challenge-002-jenkins-cp
fi

if [ ! -f jenkins_jazzer_seeds.tar.gz ]; then
    mkdir -p jenkins_jazzer_seeds
    pushd jenkins_jazzer_seeds
    echo "foobar" > 1
    tar -czvf ../jenkins_jazzer_seeds.tar.gz .
    popd
    rm -rf ./jenkins_jazzer_seeds
fi

if [ ! -d "workdir" ]; then
    mkdir workdir
    pushd workdir

    tar -xf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    patch -p1 ./container_scripts/PipelineCommandUtilPovRunner.java < ../harness.patch

    ./run.sh build

    mkdir inputs
    pushd inputs
    tar -xf ../../jenkins_jazzer_seeds.tar.gz
    popd

    popd
fi

pushd workdir

docker login ghcr.io -u player-c3f09220 -p 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

jq -r '.["#select"].tuples[][] | gsub("\\n"; "") | select(length > 0) | @json' $CUR_DIR/fuzz_jenkins/dict.json > ./dict.txt
cp $CUR_DIR/../jazzer/jazzer_modifications/fuzz.sh .

if [ -f Dockerfile.bak ]; then
    cp Dockerfile.bak Dockerfile
fi
cp Dockerfile Dockerfile.bak
echo "RUN apt -y update && apt -y install vim" >> Dockerfile

echo "COPY ./src /cp-src" >> Dockerfile
echo "COPY ./out /out" >> Dockerfile
echo "ADD ./inputs /inputs" >> Dockerfile
cat $CUR_DIR/../jazzer/jazzer_modifications/Dockerfile.extensions >> Dockerfile
docker build -t jazzer-jenkins-fuzzer-debug .

popd

time docker run --name jazzer_test jazzer-jenkins-fuzzer-debug /fuzz.sh -i /inputs -o /crashes -- /usr/local/sbin/PipelineCommandUtilPovRunner.java
