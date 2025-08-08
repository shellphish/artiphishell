#!/bin/bash

set -xe

cd $(dirname "$0")

#mkdir -p mods/litellm/proxy
#cp litellm/litellm/proxy/proxy_server.py mods/litellm/proxy/

#mkdir -p mods/litellm/litellm_core_utils
#cp litellm/litellm/litellm_core_utils/litellm_logging.py mods/litellm/litellm_core_utils/

cp litellm/litellm/cost_calculator.py mods/litellm/

mkdir -p mods/litellm/litellm_core_utils/llm_cost_calc
cp litellm/litellm/litellm_core_utils/llm_cost_calc/utils.py mods/litellm/litellm_core_utils/llm_cost_calc/

mkdir -p mods/litellm/llms/openai
cp litellm/litellm/llms/openai/cost_calculation.py mods/litellm/llms/openai/

./build.sh --push

LITELLM_POD=$(kubectl get pod -l app.kubernetes.io/name=litellm -o jsonpath='{.items[0].metadata.name}')

kubectl delete pod $LITELLM_POD --force

