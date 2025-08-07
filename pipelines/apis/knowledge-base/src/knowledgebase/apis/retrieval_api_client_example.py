import requests
import numpy as np
import time

def get_embeddings(text):

    api_url = 'http://beatty.unfiltered.seclab.cs.ucsb.edu:49152'
    endpoint_url = f'{api_url}/embed'
    model = 'oai-text-embedding-3-small'
    auth_key = '!!Shellphish!!'
    response = requests.post(endpoint_url, json={'text':text, 'model': model, 'auth_key': auth_key})

    if response.status_code != 200:
        print(f'Embeddings URL failed, code: {response.status_code}')
    else:
        results = response.json()
        embeddings = np.asarray(results['embedding'])

        return embeddings

source_code = 'tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)'
emb = get_embeddings(source_code)
print(emb.shape)


res = requests.post(f'http://beatty.unfiltered.seclab.cs.ucsb.edu:48751/api/info/available_kbs', json={
"auth_key": '!!Shellphish!!'
})

kb_names = res.json()

print(f'available knowledge bases: {kb_names}')

endpoints = ['closest_vuln', 'closest_diff']

source_code = 'tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)'

for ep in endpoints:
    for kb_name in kb_names:
      print(f'Testing: {ep} for {kb_name}')
      # FOR RETRIEVING PATCHED FUNCTIONS FROM CLOSEST VULNERABLE FUNCTION 
      res = requests.post(f'http://beatty.unfiltered.seclab.cs.ucsb.edu:48751/api/funcs/{ep}', json={
        "query": source_code, # source code goes there
        "num_return": 10, # how many similar functions you're retrieving
        "auth_key": '!!Shellphish!!',
        "knowledge_base": kb_name
      })
      
      start = time.time()
      res = res.json()['result']
      print(len(res))
      print(res[0].keys())
      print([r['score'] for r in res]) 
      print(f'Took {time.time() - start} seconds')
