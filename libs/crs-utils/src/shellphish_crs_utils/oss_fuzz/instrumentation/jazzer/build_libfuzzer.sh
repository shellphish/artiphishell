#!/bin/bash

set -eux

LIBFUZZER_REPO=$SRC/shellphish/libfuzzer-jazzer
JAZZER_REPO=$SRC/shellphish/jazzer-aixcc/

PARENT_DIR=$(dirname $LIBFUZZER_REPO)
OUT_FILE="$(basename $LIBFUZZER_REPO).tar.gz"

BAZEL_FILE=$JAZZER_REPO/MODULE.bazel

echo "Building jazzer from $LIBFUZZER_REPO"

if [ -f "$OUT_FILE" ]; then
    rm -rf $OUT_FILE
fi

# pushd $SRC/shellphish/
LIBFUZZER_REPO_NAME=$(basename $LIBFUZZER_REPO)
tar --use-compress-program=pigz -C $SRC/shellphish/ -cf $OUT_FILE $LIBFUZZER_REPO_NAME
# popd

SHASUM=$(sha256sum $OUT_FILE | cut -d' ' -f1)
URL="http://localhost:8000/$OUT_FILE"
PREFIX="$(basename $LIBFUZZER_REPO)/compiler-rt/lib/fuzzer"

## Fix the SHA
line_num=$(awk '/jazzer_libfuzzer/,/\)/ { if ($0 ~ /^ *sha256 *=/) print NR }' $BAZEL_FILE)
sed -i "${line_num}s|^.*\$|    sha256 = \"${SHASUM}\",|" $BAZEL_FILE

## Fix the PREFIX
line_num=$(awk '/jazzer_libfuzzer/,/\)/ { if ($0 ~ /^ *strip_prefix *=/) print NR }' $BAZEL_FILE)
sed -i "${line_num}s|^.*\$|    strip_prefix = \"${PREFIX}\",|" $BAZEL_FILE

## Fix the URL
line_num=$(awk '/jazzer_libfuzzer/,/\)/ { if ($0 ~ /^ *url *=/) print NR }' $BAZEL_FILE)
sed -i "${line_num}s|^.*\$|    url = \"${URL}\",|" $BAZEL_FILE

ls -al $SRC/shellphish/

# launch a python server to serve the tar file
python3 -m http.server 8000 --directory $PARENT_DIR &
SERVER_PID=$!

pushd $JAZZER_REPO
rm -rf $(bazel info output_base)/external
bazel shutdown
# bazel build //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar //deploy:jazzer-api //deploy:jazzer-junit //launcher:jazzer

bazel build //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar //deploy:jazzer-api //deploy:jazzer-junit //launcher:jazzer

# if [ -d "jazz-build" ]; then
#     rm -rf jazz-build
# fi

kill $SERVER_PID
mkdir jazzer-build
cp $(bazel cquery --output=files //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar) $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_agent_deploy.jar
cp $(bazel cquery --output=files //launcher:jazzer) $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_driver

popd

echo "Leaving jazzer build in $JAZZER_REPO"
