
#!/bin/bash -u

set -eux

CURR_DIR=$(pwd)
CURR_USER=$(whoami)
TARGET_NAME=cups

export CURR_DIR=$CURR_DIR
export CURR_USER=$CURR_USER

# If the CURR_DIR starts with /shellphish/coverageguy it means we are testing locally in our devcontainer
# We can simply run the internal test
if [[ $CURR_DIR == /shellphish/coverageguy* ]]; then
    ./ci_tests/$TARGET_NAME/test-$TARGET_NAME.sh
else
    # During CI tests (or outside the .devcontainer) we must be in the coverageguy directory
    # thus, let's check if the current directory simply ends with coverageguy
    if [[ $CURR_DIR != *coverage-guy ]]; then
        echo "The current directory does not end with coverageguy. Please run this script from the coverageguy directory."
        exit 1
    fi
    mkdir -p /shared/ci_tests/
    # 1- Rebuild the coverageguy container
    docker build . -t coverageguy:latest
    # 2- Run the test in the container!
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $CURR_DIR/ci_tests/:/shellphish/coverageguy/ci_tests/ -v /shared:/shared coverageguy:latest /bin/bash -c "chmod +x /shellphish/coverageguy/ci_tests/$TARGET_NAME/test-$TARGET_NAME.sh && /shellphish/coverageguy/ci_tests/$TARGET_NAME/test-$TARGET_NAME.sh"
fi

