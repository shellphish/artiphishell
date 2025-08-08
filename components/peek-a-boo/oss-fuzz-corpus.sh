#!/bin/bash
# OSS-Fuzz Corpus Generator Script

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if python is available
if ! command_exists python3; then
    echo "Error: Python 3 is required but not installed. Please install Python 3 and try again."
    exit 1
fi


# Create temporary directory and clone OSS-Fuzz
TMP_DIR="/tmp/peek-a-boo"
mkdir -p "$TMP_DIR"
pushd "$TMP_DIR" > /dev/null

# Check if oss-fuzz already exists in this directory
if [ ! -d "$TMP_DIR/oss-fuzz" ]; then
    echo "Cloning OSS-Fuzz repository..."
    git clone https://github.com/google/oss-fuzz.git
fi
# Set OSS-Fuzz directory
OSS_FUZZ_DIR="$TMP_DIR/oss-fuzz"
popd

# Get project name and harness name from user
read -p "Enter the project name: " PROJECT_NAME
read -p "Enter the harness/fuzzer name: " HARNESS_NAME
read -p "Enter sanitizer (address/memory/undefined) [default: coverage]: " SANITIZER
read -p "Enter the custom corpus directory [default: ../../components/corpus-guy/oss-fuzz-sat-corpus/$PROJECT_NAME/$HARNESS_NAME]: " USER_CORPUS_DIR
read -p "Enter the port number [default: 8090]: " USER_PORT_NUM

#TODO: if you don't have oss-fuzz-sat-corpus, download it from beatty

# Set defaults if not provided
SANITIZER=${SANITIZER:-coverage}
PORT_NUM=${USER_PORT_NUM:-8090}

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Set corpus directory default if not provided
if [ -z "$USER_CORPUS_DIR" ]; then
    CORPUS_DIR="$SCRIPT_PATH/../corpus-guy/oss-fuzz-sat-corpus/$PROJECT_NAME/$HARNESS_NAME"
else
    CORPUS_DIR="$USER_CORPUS_DIR"
fi

# Check if corpus directory exists
if [ ! -d "$CORPUS_DIR" ]; then
    echo "Warning: Custom corpus directory $CORPUS_DIR does not exist."
    read -p "Do you want to create it? (y/n) [default: y]: " CREATE_DIR
    CREATE_DIR=${CREATE_DIR:-y}
    
    if [[ "$CREATE_DIR" == "y" || "$CREATE_DIR" == "Y" ]]; then
        mkdir -p "$CORPUS_DIR"
        echo "Created directory: $CORPUS_DIR"
    else
        echo "Error: Cannot proceed without a valid corpus directory."
        exit 1
    fi
fi

pushd "$OSS_FUZZ_DIR/.." > /dev/null
mkdir -p oss-fuzz-sat-corpus/"$PROJECT_NAME"/"$HARNESS_NAME"/
cp $CORPUS_DIR/public.zip  $PROJECT_NAME/$HARNESS_NAME/
unzip   $PROJECT_NAME/$HARNESS_NAME/public.zip -d $PROJECT_NAME/$HARNESS_NAME/
rm $PROJECT_NAME/$HARNESS_NAME/public.zip
popd > /dev/null


echo "===== Building project and fuzzer ====="
pushd "$OSS_FUZZ_DIR" > /dev/null

# Build the Docker image for the project
echo "Building Docker image for $PROJECT_NAME..."
python3 infra/helper.py build_image "$PROJECT_NAME"

# Build the fuzzers with specified sanitizer
echo "Building fuzzers for $PROJECT_NAME with sanitizer=$SANITIZER..."
python3 infra/helper.py build_fuzzers --sanitizer "$SANITIZER" "$PROJECT_NAME"

echo "===== Running coverage analysis ====="
# Run coverage analysis with custom corpus directory
echo "Running coverage analysis for $PROJECT_NAME with custom corpus directory..."
python3 infra/helper.py coverage "$PROJECT_NAME" --no-corpus-download --corpus-dir="$CORPUS_DIR" --fuzz-target="$HARNESS_NAME" --port="$PORT_NUM"

popd > /dev/null

echo "===== Process completed ====="
echo "Project: $PROJECT_NAME"
echo "Harness: $HARNESS_NAME"
echo "Sanitizer: $SANITIZER"
echo "Custom corpus directory: $CORPUS_DIR"
echo "Port number: $PORT_NUM"

exit 0