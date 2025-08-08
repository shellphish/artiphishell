#!/bin/bash

cd $(dirname $0)

set -ex

# The flask app variable is located in src.server

gunicorn -w 4 -b 0.0.0.0:${API_PORT:-1337} --access-logfile - --capture-output --log-level debug --timeout 300 src.server:app