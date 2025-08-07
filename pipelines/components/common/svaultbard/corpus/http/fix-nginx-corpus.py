import io
import os
import sys

import yaml

nginx_corpus = sys.argv[1]
request_corpus = sys.argv[2]
response_corpus = sys.argv[3]
os.makedirs(request_corpus, exist_ok=True)
os.makedirs(response_corpus, exist_ok=True)
for root, dirs, files in os.walk(nginx_corpus):
    for file in files:
        with open(os.path.join(root, file), 'rb') as f:
            data = f.read()
            try:
                result = yaml.safe_load(io.BytesIO(data))
                request = result.get('request', None)
                response = result.get('response', None)
            except Exception as e:
                pass
            if not request:
                try:
                    request = yaml.safe_load(io.StringIO(data.split('request:')[1].split('\n')[0].strip()))
                except:
                    request = None
            if not response:
                try:
                    response = yaml.safe_load(io.StringIO(data.split('response:')[1].split('\n')[0].strip()))
                except:
                    response = None

            if request:
                with open(os.path.join(request_corpus, file), 'w') as f:
                    f.write(request)
            if response:
                with open(os.path.join(response_corpus, file), 'w') as f:
                    f.write(response)
