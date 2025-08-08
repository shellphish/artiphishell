#!/bin/bash

set -x
set -e

# LITELLM_KEY=${LITELLM_KEY:sk-artiphishell-da-best!!!}
# AIXCC_LITELLM_HOSTNAME=${AIXCC_LITELLM_HOSTNAME:-http://beatty.unfiltered.seclab.cs.ucsb.edu:4000/}
export OPENAI_API_KEY="$(cat $(realpath ../../../../../../../openai.key))"

# if no variable given print stuff
if [ -z "$1" ]; then
    echo "Usage: $0 <target_name>"
    exit 1
fi

docker login ghcr.io -u zebck -p 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
pushd ../../../local_run/
./rebuild_local.sh build
popd

pushd ../
docker build -t aixcc-grammar-guy .
popd

if [ $1 == "nginx" ]; then
    
    export TARGET_NAME="targets-semis-aixcc-sc-challenge-004-nginx-cp"

elif [ $1 == "jxmlbuilder" ]; then
    
    export TARGET_NAME="targets-semis-java-xmlbuilder"

elif [ $1 == "oniguruma-1" ]; then

    export TARGET_NAME="targets-semis-oniguruma-25893"

elif [ $1 == "p11-kit-57202" ]; then

    export TARGET_NAME="targets-semis-p11-kit-57202"

elif [ $1 == "selinux-31124" ]; then

    export TARGET_NAME="targets-semis-selinux-31124"

else
    echo "Target name not yet supported. Please add to run.sh"
    exit 1
fi

# check if folder already pulled
if [ ! -d $TARGET_NAME ]; then
    git clone "https://github.com/shellphish-support-syndicate/${TARGET_NAME}.git"
    (
        pushd $TARGET_NAME
        set -x
        make cpsrc-prepare && make docker-pull
        popd
    )
fi

# check if folder already compressed for injection
if [ ! -f "${TARGET_NAME}.tar.gz" ]; then
    tar czf "${TARGET_NAME}.tar.gz" -C $TARGET_NAME .
fi

pdl --unlock || rm -rf pipeline.lock
pdl --name "grammar_guy_feature_test_${TARGET_NAME}" # --ignore-required
pd inject analyze_target.target_with_sources 1 < "${TARGET_NAME}.tar.gz"
echo "works: true" | pd inject coverage_build.project_id 1
# ./restore_backup.sh $1 # backup to restore_latest_state
#pd --verbose --global-script-env "LITELLM_KEY=$LITELLM_KEY" --global-script-env "AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME" run #-t grammar_guy_build -t grammar_guy_fuzz run
pd --verbose --global-script-env USE_LLM_API="False" --global-script-env OPENAI_API_KEY=$OPENAI_API_KEY run # without LiteLLM API
