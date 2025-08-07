import requests
import json

# Base URL for your LiteLLM API
base_url = "http://localhost:4000"

# Master key for authentication
master_key = "sk-artiphishell"

# Headers for the requests
headers = {
    "Authorization": f"Bearer {master_key}",
    "Content-Type": "application/json"
}

# Step 1: Generate a new key
generate_key_endpoint = f"{base_url}/key/generate"
response = requests.post(generate_key_endpoint, headers=headers, data=json.dumps({}))

if response.status_code == 200:
    key_data = response.json()
    new_key = key_data["key"]
    print(f"Generated Key: {new_key}")
else:
    print(f"Failed to generate key: {response.status_code} - {response.text}")
    exit()

# Step 2: Update the key with the desired models
update_key_endpoint = f"{base_url}/key/update"
models = [
    "oai-gpt-4o",
    "oai-gpt-3.5-turbo",
    "oai-gpt-4",
    "oai-gpt-4-turbo",
    "text-embedding-3-large",
    "text-embedding-3-small",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3.5-sonnet",
    "claude-3-haiku"
]

update_payload = {
    "key": new_key,
    "models": models
}

response = requests.post(update_key_endpoint, headers=headers, data=json.dumps(update_payload))

if response.status_code == 200:
    print(f"Successfully updated key with models: {models}")
else:
    print(f"Failed to update key: {response.status_code} - {response.text}")
    exit()

# Step 3: Perform a query using a model
query_endpoint = f"{base_url}/chat/completions"
query_headers = {
    "Authorization": f"Bearer {new_key}",
    "Content-Type": "application/json"
}

query_payload = json.dumps({
    "model": "oai-gpt-4o",
    "messages": [
    {
      "content": "Hello, whats the weather in San Francisco??",
      "role": "user"
    }
  ]
})

response = requests.post(query_endpoint, headers=query_headers, data=query_payload)

if response.status_code == 200:
    query_result = response.json()
    print(f"Query Result: {json.dumps(query_result, indent=2)}")
    if 'cost' in query_result:
        print(f"Query Cost: {query_result['cost']}")
else:
    print(f"Failed to perform query: {response.status_code} - {response.text}")
    exit()
