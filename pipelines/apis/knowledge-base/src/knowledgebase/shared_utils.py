import io
import logging
import os
from datetime import datetime

from .settings import AUTH_KEY


# given the parsed details of a function/method from the ParserAPI, create a unique string/identifier for that function
def create_function_identifier(f_dict):
    return f'{f_dict["full_name"]}::{f_dict.get("access", "unknown")}::{f_dict["signature"]}::{f_dict["return_type"]}'

# TODO --- replace these with the real deal
# ideally, these functions reformat the code, does some linting and cleaning up to minimize the effects
# of formatting differences in computing embeddings
def reformatter(source_code:str, code_type:str):

    if code_type == 'function':
        return _reformatter_function(source_code)
    elif code_type == 'func_diff':
        return _reformatter_diff(source_code)
    elif code_type == 'file':
        return _reformatter_file(source_code)
    elif code_type == 'file_diff':
        return _reformatter_diff(source_code)
    else:
        logging.info(f'Reformatter, unknown code_type:{code_type}')
        return _reformatter_function(source_code)

def _reformatter_file(file_content:str):
    return file_content

def _reformatter_function(function_content:str):
    return function_content

def _reformatter_diff(diff_content:str):
    return diff_content


# to fetch a file from a specific commit of the github repo
class CommitFile:
    def __init__(self, repo, commit_sha, file_path, bytes=False):
        commit = repo.commit(commit_sha)
        file = commit.tree / file_path
        with io.BytesIO(file.data_stream.read()) as f:
            cnts = f.read()
            if not bytes:
                cnts = cnts.decode('utf-8')

        self.contents = cnts
        self.extension = os.path.splitext(file_path)[1]


class TargetFile:
    def __init__(self, fpath, bytes=False):
        with open(fpath, 'rb') as fp:
            cnts = fp.read()
            if not bytes:
                cnts = cnts.decode('utf-8')

        self.contents = cnts

def is_authorized(data):
    if request_auth_key := data.get('auth_key', '') != AUTH_KEY:
        logging.warning(f'Request sent with wrong auth key: {request_auth_key}')
        return False
    else:
        return True
    
def to_epoch_ts(time_string):

    # Parse the time string into a datetime object
    datetime_obj = datetime.strptime(time_string, '%Y/%m/%d %H:%M')

    # Convert the datetime object to a timestamp
    epoch_timestamp = int(datetime_obj.timestamp())

    return epoch_timestamp