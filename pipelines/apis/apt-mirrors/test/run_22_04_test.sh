#!/usr/bin/bash

docker network create --internal isolated-network
docker run -d --network=isolated-network --name=apt-mirror-22-04 aixcc-apt-mirror:22.04
pushd $(dirname $0)
docker build . -t test-container:22.04 -f Dockerfile.22.04.test
docker run --rm -it --network=isolated-network test-container:22.04 /bin/bash
#docker run --rm --network=isolated-network test-container:22.04 /bin/bash -c "apt update && apt install -y curl g++ gcc && curl http://apt-mirror-2204" | tee /tmp/package-out
docker kill apt-mirror-2204
docker rm apt-mirror-2204
popd

if grep -q "<html>" /tmp/package-out; then
  echo "Test Succeeded"
  exit 0
else
  echo "Test Failed"
  exit 0
fi
