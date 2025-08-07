import logging
import gc
import math
import torch

from sentence_transformers import SentenceTransformer
from transformers import AutoModel, AutoTokenizer


# initiate this in the runtime
SPECIAL_TOKENS_PER_MODEL = {}
DEFAULT_LOCAL_MODEL = 'codet5p-110m-embedding'


class HFModelWrapper:
    def __init__(self, checkpoint, device='cpu'):
        self.device = device
        local_path = path_converter(checkpoint)
        self.tokenizer = AutoTokenizer.from_pretrained(local_path) 
        self.model = AutoModel.from_pretrained(local_path, trust_remote_code=True).to(self.device)
        self.max_seq_length = self.tokenizer.model_max_length

    def encode(self, text,  *args, **kwargs):
        inputs = self.tokenizer.encode(text, return_tensors="pt").to(self.device)
        embedding = self.model(inputs)[0]
        return embedding.detach().cpu()
    
    def forward(self, inputs_dict):
        return {'sentence_embedding':self.model(inputs_dict['input_ids'])}


def clean_memory():
    gc.collect()

    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def sample_chunks(chunks, max_chunks=6):

    num_chunks = len(chunks)

    if num_chunks <= max_chunks or max_chunks == -1:
        return chunks
    
    else:

        mc = 3*math.ceil(max_chunks/3)

        chunk_ids = list(range(num_chunks))

        from_each_section = mc//3

        beg = chunk_ids[:from_each_section] 
        mid = chunk_ids[(num_chunks//2)-(from_each_section//2):(num_chunks//2)+(math.ceil(from_each_section/2))]
        end = chunk_ids[-from_each_section:]

        new_chunk_ids = sorted(list(set(beg+mid+end)))
        return [chunks[ii] for ii in new_chunk_ids]                         


# for text longer than the max context length, overlap size determines the overlap between the sliding windows -- between i_th and (i+1)_th windows
def encode_wrapper(model_name, text, overlap_size=0.1):

    model = EMBEDDING_LOCAL_MODELS.get(model_name, DEFAULT_LOCAL_MODEL)

    toks = model.tokenizer.encode(text, truncation=False)
    rem_toks = toks[1:-1]
    max_toks = model.max_seq_length

    # begin sequence, pad token and end sequence tokens
    if model_name not in SPECIAL_TOKENS_PER_MODEL:
        special_tokens = model.tokenizer.encode(model.tokenizer.pad_token, truncation=False)
        SPECIAL_TOKENS_PER_MODEL[model_name] = special_tokens
    else:
        special_tokens = SPECIAL_TOKENS_PER_MODEL[model_name]

    if overlap_size > 0 and overlap_size < 1: # proportional to max len
        overlap_size = int(max_toks*overlap_size)
    
    if len(toks) > max_toks:
        # split the text into chunks
        chunks = [pad(special_tokens, max_toks, rem_toks[i:i+(max_toks-2)]) for  i in range(0, len(rem_toks), max_toks-2-overlap_size)]

        chunks = sample_chunks(chunks, MAX_CHUNKS_PER_TEXT)

        chunks, attention = list(zip(*chunks))

        all_ch_embs = model.forward(chunk_to_dict(chunks, attention, model.device))['sentence_embedding']

        embs_ret = all_ch_embs.mean(axis=0).tolist()

        del chunks, attention, all_ch_embs

    else:
        embs_ret = model.encode(text, convert_to_tensor=True, device=model.device).tolist()

    del toks

    clean_memory()

    return embs_ret


def chunk_to_dict(chunk, attn, device):
    return {'input_ids': torch.LongTensor(chunk).to(device), 'attention_mask': torch.LongTensor(attn).to(device)}


def pad(special_tokens, max_len, seq):

    num_pad = max_len - len(seq) - 2

    padding = [special_tokens[1]] * num_pad

    padded_seq = [special_tokens[0], *seq, special_tokens[-1],  *padding]

    attention_mask = [1]*(max_len-num_pad) + [0]*num_pad

    return padded_seq, attention_mask


def path_converter(checkpoint):
    local_path = f"/app/model_{checkpoint.split('/')[1]}" # load from the local dir created in download_models.py
    return local_path

def st_load(checkpoint):
    return SentenceTransformer(path_converter(checkpoint))


logging.info("Loading the local models for Embeddings API...")
st_codesearch_distilroberta_base_model = st_load(checkpoint="flax-sentence-embeddings/st-codesearch-distilroberta-base")
codet5p_110m_embedding = HFModelWrapper(checkpoint='Salesforce/codet5p-110m-embedding', device=st_codesearch_distilroberta_base_model._target_device)


MAX_CHUNKS_PER_TEXT = 6
# MAX_CHUNKS_PER_TEXT = -1


EMBEDDING_LOCAL_MODELS = {
    "st-codesearch-distilroberta-base": st_codesearch_distilroberta_base_model,
    "codet5p-110m-embedding": codet5p_110m_embedding
}
