
#!/bin/bash

set -x

cd $(dirname $0)

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"


if [ "$1" == "--build" ]; then

if [ -d litellm ]; then
    echo "litellm directory already exists"
else
    git clone https://github.com/BerriAI/litellm
fi


pushd litellm
docker compose build
popd

fi

echo 'LITELLM_MASTER_KEY="sk-1234"' > .env

echo 'LITELLM_SALT_KEY="sk-1234"' >> .env

source .env

DOCKER_IMAGE_NAME="$EXTERNAL_REGISTRY/aixcc-litellm:latest"

docker build -t $DOCKER_IMAGE_NAME . $1


