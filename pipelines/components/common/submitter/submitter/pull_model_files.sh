#!/usr/bin/bash
set -e
set -x

FILE_DIR=$(dirname $(realpath $0))
pushd $FILE_DIR
git clone https://github.com/shellphish-support-syndicate/aixcc-sc-capi.git
cp aixcc-sc-capi/competition_api/models/* ./models
for f in $(find ./models -type f); do
    sed -i 's/competition_api\.models//g' $f
done
rm -rf aixcc-sc-capi
popd
