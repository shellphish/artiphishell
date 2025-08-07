import requests
import numpy as np
import time

EMB_API_URL = 'http://beatty.unfiltered.seclab.cs.ucsb.edu'
# EMB_API_URL = 'http://172.17.0.2'

# EMB_API_PORT = 49153
EMB_API_PORT = 49152

# MODEL = "codet5p-110m-embedding"
MODEL =  "oai-text-embedding-3-small"

AUTH_KEY = '!!Shellphish!!'


def get_embeddings(text, num_repeat=1):

    api_url = f'{EMB_API_URL}:{EMB_API_PORT}'

    if num_repeat > 1:
        endpoint_url = f'{api_url}/embed_batch'
        response = requests.post(endpoint_url, json={'texts':[text] * num_repeat, 'model': MODEL, 'auth_key': AUTH_KEY})

        if response.status_code != 200:
            print(f'Embeddings URL failed, code: {response.json()["error"]}')
        else:
            results = response.json()['results']
            embeddings = [np.asarray(r['embedding']) for r in results]
            return embeddings

    else:
        endpoint_url = f'{api_url}/embed'
        response = requests.post(endpoint_url, json={'text':text, 'model': MODEL, 'auth_key': AUTH_KEY})

        if response.status_code != 200:
            print(f'Embeddings URL failed, code: {response.json()["error"]}')
    
        else:
            results = response.json()
            embeddings = np.asarray(results['embedding'])
            return embeddings



mult = 10
source_code = 'tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)'
source_code = source_code * mult

start = time.time()
emb = get_embeddings(source_code)
end = time.time()

print(f'emb len: {len(emb)}, {np.mean(emb)} - took : {end - start} seconds for {len(source_code)} characters input')


nr = 5

start = time.time()
emb = get_embeddings(source_code, num_repeat=nr)
end = time.time()

print(f'emb-batch len: {len(emb)}, for nr: {nr} - {np.mean(emb[0])} - took : {end - start} seconds for {len(source_code)} characters input')
