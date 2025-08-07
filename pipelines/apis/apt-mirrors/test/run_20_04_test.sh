#!/usr/bin/bash

docker network create --internal isolated-network
docker run -d --network=isolated-network --name=apt-mirror-20-04 aixcc-apt-mirror:20.04
pushd $(dirname $0)
docker build . -t test-container:20.04 -f Dockerfile.20.04.test
docker run --rm -it --network=isolated-network test-container:20.04 /bin/bash
docker kill apt-mirror-2004
docker rm apt-mirror-2004
popd

if grep -q "<html>" /tmp/package-out; then
  echo "Test Succeeded"
  exit 0
else
  echo "Test Failed"
  exit 0
fi
