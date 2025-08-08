#!/bin/bash

set -ex

SCRIPT_DIR=$(realpath $(dirname $0))

export PATH="/app/.venv/bin:$PATH"

# Wait for the vllm server to start
sleep 60

set +e

for i in {1..20}; do
    if curl http://vllm-server:25002/v1/completions \
      -H "Content-Type: application/json" \
      -d '{
        "model": "/models/final_model",
        "prompt": "CRS stands for ",
        "max_tokens": 8192,
        "temperature": 0
      }'; then
        break
    fi
    echo "Attempt $i failed, retrying..."
    sleep 20
done

python3 vuln_scan.py \
--model_name /models/final_model \
--server_url http://vllm-server:25002/v1/ \
--language $LANGUAGE \
--clang_indices $FUNCTIONS_JSON_DIR