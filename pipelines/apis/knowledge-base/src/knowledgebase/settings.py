import os
from neomodel import config

config.DATABASE_URL = os.environ.get('_NEO4J_URL', 'bolt://knowledge-base:7687')
# config.DATABASE_URL = 'bolt://neo4j:!!Shellphish!!@beatty.unfiltered.seclab.cs.ucsb.edu:7689'

AUTH_KEY = '!!Shellphish!!'
AUTH_FAIL_RESPONSE = {'status': 'auth_fail'}


## Retrieval config
DEFAULT_EMBEDDING_MODEL = 'oai-text-embedding-3-small'
SIMILARITY_FUNCTION = "cosine"
LINUX_KERNEL_FILE_SUFFICES = ['cpp', 'c', 'h', 'hpp', 'cc']
JAVA_FILE_SUFFICES = ['java']

## VECTOR INDEXES CREATED FOR NEO4J RETRIEVAL
INDEXES = {
    "function_patch":
        {
            "node_name": "FunctionModification",
            "indexes":
                {
                    'retrieve_vuln_function':
                        {
                            'property': 'beforePatchEmbeddings'
                        },

                    'retrieve_patched_function':
                        {
                            'property': 'afterPatchEmbeddings'
                        },
                    
                    'retrieve_similar_diff':
                        {
                            'property': 'patchDiffEmbeddings'
                        }

                }
        }
}
