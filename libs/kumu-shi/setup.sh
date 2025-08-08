#!/bin/bash

# check if the user has docker and git installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed, please install docker and try again"
  exit 1
fi
if ! command -v git &> /dev/null; then
  echo "Git is not installed, please install git and try again"
  exit 1
fi

# first, check if ./artiphishell-tests-data exists, if not do copy and clone checks
if [ ! -d "./artiphishell-tests-data" ]; then
  # does it exist in ../../../?, then cp it, else clone
  if [ -d "../../../artiphishell-tests-data" ]; then
    echo "Copying test data from ../../../artiphishell-tests-data"
    cp -r ../../../artiphishell-tests-data ./artiphishell-tests-data
  else
    echo "Cloning test data from GitHub..."
    git clone git@github.com:shellphish-support-syndicate/artiphishell-tests-data.git ./artiphishell-tests-data
  fi
fi

# build the docker image
#docker build . --build-arg IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/ -t aixcc-patchery

# link the test data to the correct places
echo "Linking test data to the correct places..."
(
  cd ./tests/ && \
  ln -s ../artiphishell-tests-data/patchery/targets targets
)

# install the package
echo "Installing the package..."
pip install -e ../../libs/crs-utils/ ../../libs/libcodeql/ ../../libs/coveragelib/ ../../libs/testguy
pip install -e .[test]

echo "Setup complete!"