import logging
import requests
import io

import git


from ..settings import *
from ..shared_utils import CommitFile, create_function_identifier, TargetFile


# To interact with the source code parser API (e.g., Joern)
class ParserAPI:
    def __init__(self, url:str):
        self.api_url = url
        logging.info(f'Initializing Parser API at: {self.api_url}')

    def get_functions_from_git_file_at_commit(self, repo:git.Repo, commit_sha, file_path):
            # Retrieve contents of a file at a specific commit

            file_contents = CommitFile(repo, commit_sha, file_path, bytes=False).contents

            logging.info(f'Parsing: {commit_sha} file at {file_path} commit')

            functions = self._get_all_functions_jenkins(file_contents, cmd='api/parse/methods')

            if functions is None:
                logging.error(f'get_functions_from_source_file::{commit_sha} - {file_path} failed.')

            return functions
    
    def get_functions_from_file(self, fpath):
            file_contents = TargetFile(fpath, bytes=False).contents

            logging.info(f'Parsing: {fpath} file.')

            functions = self._get_all_functions_jenkins(file_contents, cmd='api/parse/methods')

            return functions

    def get_functions_from_contents(self, file_contents):
            logging.info(f'Parsing: file contents {len(file_contents)} characters.')
            functions = self._get_all_functions_jenkins(file_contents, cmd='api/parse/methods')
            return functions

    
    def _send_request(self, code_text, cmd='api/parse/methods'):
        parser_url = f'{self.api_url}/{cmd}'
        response = requests.post(parser_url, json={'code':code_text})

        if response.status_code != 200:
            logging.error(f'Parser URL failed, code: {response.status_code}')
            return None
        else:
            results = response.json()
            return results

   
    def _get_all_functions_jenkins(self, code_text, cmd):

        results = self._send_request(code_text, cmd)

        if results is None:
            return None

        if 'targets' not in results:
            logging.error(results)
            return None
        else:
            functions = results['targets'][0]
            parsed_funcs = {}
            for f_dict in functions:
                cur_func = {
                    'full_name': f_dict['full_name'],
                    'access': f_dict.get('access', 'unknown'),
                    'signature': f_dict['signature'],
                    'return_type': f_dict['return_type'],
                    'src': f_dict['src']['source_code']
                }

                identifier = create_function_identifier(f_dict)

                parsed_funcs[identifier] = cur_func

            return parsed_funcs
        
    
    # given two lists of functions extracted from a source file, find the ones that are modified
    @staticmethod
    def find_patched_funcs(vuln_funcs, patch_funcs):
        changed_funcs = []

        for identifier in set(vuln_funcs.keys()) & set(patch_funcs.keys()):
            if vuln_funcs[identifier]['src'] != patch_funcs[identifier]['src']:
                changed_funcs.append(identifier)
        return changed_funcs

