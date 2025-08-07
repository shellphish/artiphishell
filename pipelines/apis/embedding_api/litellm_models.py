import os
import requests
from tenacity import retry, wait_fixed, stop_after_attempt
import tiktoken
from itertools import islice
import numpy as np
import logging

# Constant for OpenAI models
EMBEDDING_CTX_LENGTH = 8191

if "LITELLM_KEY" not in os.environ or "AIXCC_LITELLM_HOSTNAME" not in os.environ:
    logging.critical("EmbeddingAPI::The environment variables for LiteLLM ($LITELLM_KEY and $AIXCC_LITELLM_HOSTNAME) cannot be found. Crashing...")
    raise KeyError


EMBEDDING_LITELLM_MODELS = {
    "oai-text-embedding-3-large": 'oai-text-embedding-3-large',
    "oai-text-embedding-3-small": 'oai-text-embedding-3-small'
}

AIXCC_LITELLM_HOSTNAME = os.environ['AIXCC_LITELLM_HOSTNAME']
LITELLM_KEY = os.environ['LITELLM_KEY']

logging.warning(f"EmbeddingAPI::Using AIXCC_LITELLM_HOSTNAME: {AIXCC_LITELLM_HOSTNAME}")
# logging.info(f"Using LiteLLM Key: {LITELLM_KEY}")


DEFAULT_LITELLM_MODEL = "oai-text-embedding-3-small"


@retry(wait=wait_fixed(10), stop=stop_after_attempt(5))
def embed_single(model_name, text):
    logging.info(f"LiteLLM Proxy - Getting embedding for text of length: {len(text)}")
    headers = {
        "Authorization": f"Bearer {LITELLM_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "input": text,
        "model": EMBEDDING_LITELLM_MODELS.get(model_name, DEFAULT_LITELLM_MODEL)
    }
    try:
        response = requests.post(f"{AIXCC_LITELLM_HOSTNAME}/embeddings", headers=headers, json=payload)
        response.raise_for_status()
        embedding = response.json()['data'][0]['embedding']
        logging.info(f"Successfully got embedding of dimension: {len(embedding)}")
        return embedding
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in get_embedding: {str(e)}")
        raise

def batched(iterable, n):
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while (batch := tuple(islice(it, n))):
        yield batch

def chunked_tokens(text, model_name, chunk_length):
    logging.info(f"Chunking text of length {len(text)} into chunks of {chunk_length} tokens")
    encoding = tiktoken.encoding_for_model(model_name)
    tokens = encoding.encode(text)
    chunks_iterator = batched(tokens, chunk_length)
    return chunks_iterator

def encode_wrapper(model_name, text, overlap_size=0.1):

    oai_model = EMBEDDING_LITELLM_MODELS.get(model_name, DEFAULT_LITELLM_MODEL)
    oai_model_stripped = '-'.join(oai_model.split('-')[1:]) # strip the oai- or azure- tag inserted by AIxCC

    logging.info(f"Getting length-safe embedding for text of length {len(text)}")
    chunk_embeddings = []
    chunk_lens = []
    for chunk in chunked_tokens(text, model_name=oai_model_stripped, chunk_length=EMBEDDING_CTX_LENGTH):
        chunk_embeddings.append(embed_single(model_name=oai_model, text=chunk))
        chunk_lens.append(len(chunk))

    chunk_embeddings = np.average(chunk_embeddings, axis=0, weights=chunk_lens)
    chunk_embeddings = chunk_embeddings / np.linalg.norm(chunk_embeddings)
    chunk_embeddings = chunk_embeddings.tolist()
    return chunk_embeddings
