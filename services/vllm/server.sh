#!/bin/bash

set -ex

export PATH="/app/.venv/bin:$PATH"

MODEL_NAME=best_n_no_rationale_poc_agent_withjava_final_model_agent_h100

MODELS_ROOT=/models
num_gpus=$(nvidia-smi --query-gpu=name --format=csv,noheader | wc -l)
uv run vllm serve $MODELS_ROOT/$MODEL_NAME \
    --dtype=bfloat16 \
    --tensor-parallel-size=$num_gpus \
    --port 25002 \
    --host 0.0.0.0 \
    --enable-auto-tool-choice \
    --tool-call-parser hermes

