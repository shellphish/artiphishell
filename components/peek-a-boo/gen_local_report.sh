set -eu

PORT_NUM=${USER_PORT_NUM:-8090}

if [ ! -d "/shared/test/oss-fuzz-projects/projects" ]; then
    mkdir -p /shared/test/
    git clone https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets-exhibition3.git /shared/test/oss-fuzz-projects
fi

if [ ! -d "/shared/test/oss-fuzz-project-src" ]; then
    mkdir -p /shared/test/oss-fuzz-project-src
fi

TMP_DIR="/tmp/peek-a-boo"
mkdir -p "$TMP_DIR"
pushd "$TMP_DIR" > /dev/null

if [ ! -d "$TMP_DIR/oss-fuzz" ]; then
    echo "Cloning OSS-Fuzz repository..."
    git clone https://github.com/google/oss-fuzz.git
fi
OSS_FUZZ_DIR="$TMP_DIR/oss-fuzz"
popd

PROJECT_NAME=$1
HARNESS_NAME=$2
PROJECT_DIR="${3:-}"
PROJECT_URL="${4:-}"

# If project url is provided lets clone and build the project
if [ -n "$PROJECT_URL" ]; then
    CLONE_NAME=$(basename "$PROJECT_URL" .git)
    # check if the project directory already exists then breakout of the if condition
    if [ ! -d "/shared/test/oss-fuzz-project-src/$CLONE_NAME"]; then
        git clone "$PROJECT_URL" "/shared/test/oss-fuzz-project-src/$CLONE_NAME"
        # store the cloned folder name in PROJECT_DIR
        PROJECT_SOURCE="/shared/test/oss-fuzz-project-src/$(basename "$PROJECT_URL" .git)"
        oss-fuzz-build --sa2nitizer coverage --instrumentation coverage_fast /shared/test/oss-fuzz-projects/projects/$PROJECT_NAME --project-source $PROJECT_SOURCE
    fi
fi
PROJECT_DIR="/shared/test/oss-fuzz-projects/projects/$PROJECT_NAME"
SEEDS_TAR_FILE="$TMP_DIR/$HARNESS_NAME/$HARNESS_NAME-seeds.tar.gz"
mkdir -p "$(dirname "$SEEDS_TAR_FILE")"
echo "Downloading seeds for $PROJECT_NAME/$HARNESS_NAME from beatty.unfiltered.seclab.cs.ucsb.edu"
curl -H 'Shellphish-Secret: !!artiphishell!!' "http://beatty.unfiltered.seclab.cs.ucsb.edu:31337/download_corpus/$PROJECT_NAME/$HARNESS_NAME" --output "$SEEDS_TAR_FILE" --fail

if [ ! -f "$SEEDS_TAR_FILE" ]; then
    echo "Failed to download seeds for $PROJECT_NAME/$HARNESS_NAME"
    exit 1
fi

TARGET_OUT_DIR="$OSS_FUZZ_DIR/build/out/$PROJECT_NAME/"
mkdir -p "$TARGET_OUT_DIR"
cp -r $PROJECT_DIR/artifacts/out/* $TARGET_OUT_DIR

CORPUS_DIR="/tmp/peek-a-boo/$PROJECT_NAME/$HARNESS_NAME"
if [ -d "$CORPUS_DIR" ]; then
    echo "Removing existing directory: $CORPUS_DIR"
    rm -rf "$CORPUS_DIR"
fi
mkdir -p "$CORPUS_DIR"

echo "Extracting seeds to $CORPUS_DIR"
tar -xzf "$SEEDS_TAR_FILE" -C "$CORPUS_DIR"
SEED_COUNT=$(find "$CORPUS_DIR" -type f | wc -l)

echo "We have $SEED_COUNT seeds in $CORPUS_DIR"

pushd "$OSS_FUZZ_DIR" > /dev/null
echo "===== Running coverage analysis ====="
echo "Running coverage analysis for $PROJECT_NAME with custom corpus directory $CORPUS_DIR"
rm -rf projects/$PROJECT_NAME
rsync -ra --delete $PROJECT_DIR/ projects/$PROJECT_NAME
echo python3 infra/helper.py coverage "$PROJECT_NAME" --no-corpus-download --corpus-dir="$CORPUS_DIR" --fuzz-target="$HARNESS_NAME" --port="$PORT_NUM"
trap 'echo "Ctrl+C caught. Ignoring."' SIGINT
python3 infra/helper.py coverage "$PROJECT_NAME" --no-corpus-download --corpus-dir="$CORPUS_DIR" --fuzz-target="$HARNESS_NAME" --port="$PORT_NUM"

if [ ! -d "/peekaboo/report" ]; then
    mkdir -p /peekaboo/report
fi
if [ -d "/peekaboo/$PROJECT_NAME/$HARNESS_NAME" ]; then
    mkdir -p /peekaboo/$PROJECT_NAME/$HARNESS_NAME
fi

cp -r $OSS_FUZZ_DIR/build/out/$PROJECT_NAME/report /peekaboo/report/$PROJECT_NAME/$HARNESS_NAME