#!/bin/bash -u

set -eux

docker build . --no-cache -t grammar-composer:latest
docker run --rm grammar-composer:latest python -m pytest /shellphish/grammar-composer/tests