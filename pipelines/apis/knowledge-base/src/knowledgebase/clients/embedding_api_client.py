import logging
import requests
import numpy as np

from ..settings import *
from ..shared_utils import *


# To interact with the embeddings API
class EmbeddingsAPI:
    def __init__(self, url, auth_key):
        self.api_url = url
        self.auth_key = auth_key
        logging.info(f'Initializing Embeddings API at: {self.api_url}')
        self.av_models = self.get_available_models()
        logging.info(f'Available models at the Embeddings API: {self.av_models}')

        assert DEFAULT_EMBEDDING_MODEL in self.av_models, f'The model {DEFAULT_EMBEDDING_MODEL} is not available at Embeddings API.'

        self.default = DEFAULT_EMBEDDING_MODEL

        logging.info(f'Default Embedding model is choosen as: {self.default}')


    def get_available_models(self):
        model_url = f'{self.api_url}/list_models'
        response = requests.post(model_url, json={'auth_key': self.auth_key})
        av_models = response.json()

        av_models_w_dims = {}
        for m in av_models:

            try:
                e = self.get_code_embeddings('dummy', from_model=m)
                av_models_w_dims[m] = e.shape[0]
            except:
                continue

        return av_models_w_dims

    def get_code_embeddings(self, source_code:str, code_type='function', from_model=DEFAULT_EMBEDDING_MODEL):

        text = reformatter(source_code, code_type)

        model_url = f'{self.api_url}/embed'

        response = requests.post(model_url, json={'text':text, 'model': from_model, 'auth_key': self.auth_key})

        if response.status_code != 200:
            logging.error(f'Embeddings URL failed, code: {response.status_code}')
            return None
        else:
            results = response.json()

            if 'embedding' not in results:
                logging.error(f'error in getting embeddings: {results}')
                embeddings = np.random.randn(self.av_models.get(from_model, DEFAULT_EMBEDDING_MODEL))
                embeddings = embeddings / np.linalg.norm(embeddings)

            else:    
                embeddings = np.asarray(results['embedding'])

            return embeddings