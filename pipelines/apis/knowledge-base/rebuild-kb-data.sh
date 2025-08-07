#!/bin/bash

docker build -f Dockerfile.kb-data -t ghcr.io/aixcc-sc/asc-crs-shellphish/knowledge-base-data .
docker push ghcr.io/aixcc-sc/asc-crs-shellphish/knowledge-base-data
