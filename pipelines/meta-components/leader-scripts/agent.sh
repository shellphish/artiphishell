#!/usr/bin/env bash

cd "$(dirname "$0")" || { echo "huh?" && exit 1; }
. /root/venv/bin/activate

pd agent-http --flush-seconds 30
