#!/bin/bash

if [ -z "$1" ]; then
  OUTPUT_FILE="/dev/stdout"
else
  OUTPUT_FILE=$1
fi

function get_llm_usage() {
    NAME=$1

    curl "http://litellm:4000/customer/info?end_user_id=$NAME-budget" \
    --header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
    --header 'Content-Type: application/json' > /tmp/$NAME-usage.json
}

get_llm_usage "openai"
get_llm_usage "claude"
get_llm_usage "gemini"
get_llm_usage "grammar"
get_llm_usage "patching"

# Combine all into a single json file where each is a key (using jq)
jq -n \
  --arg openai "$(cat /tmp/openai-usage.json)" \
  --arg claude "$(cat /tmp/claude-usage.json)" \
  --arg gemini "$(cat /tmp/gemini-usage.json)" \
  --arg grammar "$(cat /tmp/grammar-usage.json)" \
  --arg patching "$(cat /tmp/patching-usage.json)" \
  '{
    openai: $openai | fromjson,
    claude: $claude | fromjson,
    gemini: $gemini | fromjson,
    grammar: $grammar | fromjson,
    patching: $patching | fromjson
  }' > $OUTPUT_FILE

if [ ! -z "$1" ]; then
  echo "Combined LLM usage data saved to $OUTPUT_FILE"
fi
