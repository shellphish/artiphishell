import os
import logging

from flask import Flask, request, jsonify
from traceback import format_exc

MODEL_TYPE = os.environ.get("EMB_MODEL_TYPE", "litellm")

logging.info(f"Running embeddings API with {MODEL_TYPE} models")

if MODEL_TYPE == 'local':
    from local_models import encode_wrapper, EMBEDDING_LOCAL_MODELS as EMBEDDING_MODELS, DEFAULT_LOCAL_MODEL as DEFAULT_MODEL
else:
    from litellm_models import encode_wrapper, EMBEDDING_LITELLM_MODELS as EMBEDDING_MODELS, DEFAULT_LITELLM_MODEL as DEFAULT_MODEL


app = Flask(__name__)


AUTH_KEY = '!!Shellphish!!'
AUTH_FAIL_RESPONSE = {'status': 'auth_fail'}
def is_authorized(data):
    if request_auth_key := data.get('auth_key', '') != AUTH_KEY:
        logging.warning(f'Request sent with wrong auth key: {request_auth_key}')
        return False
    else:
        return True
    

@app.route('/')
def openapi_spec():
    return jsonify({
        'endpoints': {
            '/embed': {
                'methods': ['POST'],
                'description': 'Embed a single text using a specified model',
                'example': {
                    'model': 'all-MiniLM-L6-v2',
                    'text': 'This is a test',
                    'auth_key': 'ENTER_YOUR_AUTH_KEY'
                },
                'response': {'status': 'success', 'model': 'all-MiniLM-L6-v2', 'embedding': [0.1, 0.2, 0.3]}
            },
            '/embed_batch': {
                'methods': ['POST'],
                'description': 'Embed a batch of texts using a specified model',
                'example': {
                    'model': 'all-MiniLM-L6-v2',
                    'texts': ['text1', 'text2', 'text3'],
                    'auth_key': 'ENTER_YOUR_AUTH_KEY'
                },
                'response': {'status': 'success', 'results': [{'status': 'success', 'embedding': [0.1, 0.2, 0.3]}, {'status': 'success', 'embedding': [0.4, 0.5, 0.6]}, {'status': 'success', 'embedding': [0.7, 0.8, 0.9]}]}
            },
            '/similarity': {
                'methods': ['POST'],
                'description': 'Compute similarity between two texts using a specified model',
                'example': {
                    'model': 'all-MiniLM-L6-v2',
                    'text_a': 'This is a test',
                    'text_b': 'This is another test',
                    'auth_key': 'ENTER_YOUR_AUTH_KEY'
                },
                'response': {'status': 'success', 'similarity': 0.9}
            },
            '/list_models': {
                'methods': ['POST'],
                'description': 'List available models',
                'example': {
                    'auth_key': 'ENTER_YOUR_AUTH_KEY'
                },
                'response': [
                    # 'all-MiniLM-L6-v2', 
                    # 'multi-qa-distilbert-cos-v1', 
                    # 'all-MiniLM-L12-v2', 
                    # 'all-distilroberta-v1', 
                    # 'multi-qa-mpnet-base-dot-v1', 
                    # 'all-mpnet-base-v2', 
                    'st-codesearch-distilroberta-base', 
                    'codet5p-110m-embedding' 
                    #open-ai-text-embedding-3-small
                    ]
            }
        }
    })


@app.route('/list_models', methods=['POST'])
def list_models():
    try:
        data = request.get_json(force=True)

        if not is_authorized(data):
            return jsonify(AUTH_FAIL_RESPONSE), 401

        return jsonify(list(EMBEDDING_MODELS.keys()))
    
    except Exception as e:
        return jsonify({'error': format_exc()}), 500


def embed_text(model_name, text):
    # any per-model custom logic can go here.
    try:
        return {
            'status': 'success',
            'model': model_name,
            'embedding': encode_wrapper(model_name, text)
            }

    except Exception as e:
        return {'status': 'error', 'error': format_exc()}

@app.route('/embed', methods=['POST'])
def embed():
    try:
        data = request.get_json(force=True)

        if not is_authorized(data):
            return jsonify(AUTH_FAIL_RESPONSE), 401

        model_name = data['model']
        if model_name not in EMBEDDING_MODELS:
            logging.warning(f'Model {model_name} not found, available models: {list(EMBEDDING_MODELS.keys())}, using {DEFAULT_MODEL}')
            model_name = DEFAULT_MODEL
        
        return jsonify(embed_text(model_name, data['text'])), 200
    
    except Exception as e:
        return jsonify({'error': format_exc()}), 500

@app.route('/embed_batch', methods=['POST'])
def embed_batch():
    try:
        data = request.get_json(force=True)

        if not is_authorized(data):
            return jsonify(AUTH_FAIL_RESPONSE), 401

        model_name = data['model']
        if model_name not in EMBEDDING_MODELS:
            logging.warning(f'Model {model_name} not found, available models: {list(EMBEDDING_MODELS.keys())}, using {DEFAULT_MODEL}')
            model_name = DEFAULT_MODEL

        result = []
        for text in data['texts']:
            result.append(embed_text(model_name, text))
        return jsonify({'status': 'success', 'results': result}), 200
    except Exception as e:
        return jsonify({'error': format_exc()}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=49152, debug=False)
