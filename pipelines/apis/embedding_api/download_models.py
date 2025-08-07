# download 
from transformers import AutoModel, AutoTokenizer
from sentence_transformers import SentenceTransformer


def path_converter(checkpoint):
    local_path = f"/app/model_{checkpoint.split('/')[1]}" # load from the local dir created in download_models.py
    return local_path


# model checkpoints from HF
name = 'Salesforce/codet5p-110m-embedding'

# fetch the models
tokenizer = AutoTokenizer.from_pretrained(name, trust_remote_code=True, force_download=True)
model = AutoModel.from_pretrained(name, trust_remote_code=True, force_download=True)

# save them under the workdir
_ = tokenizer.save_pretrained(path_converter(name))
_ = model.save_pretrained(path_converter(name))

name =  'flax-sentence-embeddings/st-codesearch-distilroberta-base'

model = SentenceTransformer(name)
model.save(path_converter(name))