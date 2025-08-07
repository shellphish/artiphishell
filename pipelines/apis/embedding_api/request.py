import requests
import time
from scipy.spatial.distance import cosine
import numpy as np
import time

# install numpy, requests packages.

supported_models = { 1: 'all_MiniLM_L6_v2',
                     2: 'multi_qa_distilbert_cos_v1', 
                    3:'all_MiniLM_L12_v2', 
                    4'all_distilroberta_v1', 
                    5:'multi_qa_mpnet_base_dot_v', 
                    6:'all_mpnet_base_v2', 
                    7:'st_codesearch_distilroberta_base'
                    }   
def sentence_embeddings(code, model_type):
    print("-------Model Type: {}--------".format(model_type))
    api_url = "http://localhost:49152/{}".format(model_type)
    start = time.time()
    response_single = requests.post(api_url, json={'code': code})
    end = time.time()
    print("total time taken : {} sec".format(end- start))

    if response_single.status_code == 200:
        result_single = response_single.json()
        embeddings = result_single['embeddings']
        return embeddings


def generate_embeddings(data, model_idx):
    model_type = supported_models[model_idx]
    # for model_type in different_sentence_models:
    #model_type = "all_mpnet_base_v2"
    print("-------Model Type: {}--------".format(model_type))
    data_keys = [key for key in data]
    data_text = [data[text_name] for text_name in data]
    embeddings = sentence_embeddings(data_text, model_type)
    embeddings_json = {}
    for text_idx in range(data_keys):
        embeddings_json[data_keys[text_idx]] = embeddings[text_idx]
    return embeddings_json


def embedding_api(data):
    print("Choose the model")
    print("1: all_MiniLM_L6_v2")
    print("2: multi_qa_distilbert_cos_v1")
    print("3: all_MiniLM_L12_v2")
    print("4: all_distilroberta_v1")
    print("5: multi_qa_mpnet_base_dot_v")
    print("6: all_mpnet_base_v2")
    print("7: st_codesearch_distilroberta_base")
    model_idx = input("Enter the model index: ")
    model_type = supported_models[int(model_idx)]
    print("-------Model: {}--------".format(model_type))
    #model_type = supported_models[model_idx]
    # for model_type in different_sentence_models:
    #model_type = "all_mpnet_base_v2"
    data_keys = [key for key in data]
    data_text = [data[text_name] for text_name in data]
    embeddings = sentence_embeddings(data_text, model_type)
    embeddings_json = {}
    for text_idx in range(data_keys):
        embeddings_json[data_keys[text_idx]] = embeddings[text_idx]
    return embeddings_json

if __name__ == "__main__":

    # inputs = [str(vulnerable), str(patched), str(diff)]
    inputs = ""
    different_sentence_models = ['all_MiniLM_L6_v2', 'multi_qa_distilbert_cos_v1', \
                                'all_MiniLM_L12_v2', 'all_distilroberta_v1', \
                                'multi_qa_mpnet_base_dot_v', 'all_mpnet_base_v2', \
                                'st_codesearch_distilroberta_base']
    
    for model_type in different_sentence_models:
        #model_type = "st_codesearch_distilroberta_base"
        embeddings = sentence_embeddings(inputs, model_type )

    import IPython
    IPython.embed()
    assert False

