# LiteLLM Proxy Configuration

This guide provides instructions on configuring and using the LiteLLM Proxy with the provided configuration file, supporting various OpenAI and Anthropic models.

## Model Alias

In the configuration, model aliases are used to simplify referencing different models. Below are the aliases and their corresponding original models:
### OpenAI Models

| Alias	|Original Model |
|-------|--------------| 
| oai-gpt-3.5-turbo	| openai/gpt-3.5-turbo-0125 |
| oai-gpt-3.5-turbo-16k	| openai/gpt-3.5-turbo-16k |
| oai-gpt-4	| openai/gpt-4-0613 |
| oai-gpt-4-turbo	| openai/gpt-4-turbo-2024-04-09k |

### Anthropic Models

| Alias	|Original Model |
|-------|--------------| 
| claude-3-opus	| claude-3-opus-20240229 |
| claude-3-sonnet | claude-3-sonnet-20240229 |
| claude-3.5-sonnet	| claude-3-5-sonnet-20240620 |
| claude-3-haiku	| claude-3-haiku-20240307 |


## Generate API Key with Specific Models

To generate an API key with access to specific models, use the following curl commands. The first command generates the key, and the second command updates it with the desired models.

### Step 1: Generate a new key

```bash
curl -X POST http://localhost:4000/key/generate -H "Authorization: Bearer sk-artiphishell" -H "Content-Type: application/json" -d '{}'
```
The above command wont give you access to any model, but serves as a sanity check that everything is working correctly

### Step2: Update the recieved key to get access to specifc models
```bash
curl -X POST http://localhost:4000/key/update -H "Authorization: Bearer sk-artiphishell" -H "Content-Type: application/json" -d '{
  "key": "YOUR_GENERATED_KEY",
  "models": [
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
}'
```
Replace *YOUR_GENERATED_KEY* with the key you received from the first command.



## Note
1. There is a python file called *test.py* that contains a sample example on how to interact with Litellm.
2. Vertex Models (Gemini's) are not supported yet, I (*@D3xt3r*) will fix it
