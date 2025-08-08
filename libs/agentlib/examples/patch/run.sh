#!/bin/bash

cd $(dirname $0)

docker compose build

docker compose run -w /app/examples/patch runner python3 ./main.py