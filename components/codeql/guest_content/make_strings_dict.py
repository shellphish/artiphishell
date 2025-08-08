import json
import os
import sys
import string

import yaml

# load merged codeql_results.json
with open(sys.argv[1], 'r') as f:
    data = yaml.safe_load(f)

strings_key = sys.argv[2]

result_reachability = {}

assert data[strings_key]['#select']['columns'] == [{'kind': 'String'}]
strings = [v[0] for v in data[strings_key]['#select']['tuples']]

allowed_chars = string.ascii_letters + string.digits + r"""!#$%&()*+,-./:;<=>?@[]^_{|}~""" + ' '
def libfuzzer_dict_encode(s):
    result = '"'
    for c in s:
        if c == '"':
            result += '\\"'
        elif c == '\\':
            result += '\\\\'
        elif c in allowed_chars:
            result += c
        else:
            result += '\\x' + f'{ord(c):02x}'
    result += '"'
    return result
result = ''
for s in strings:
    result += libfuzzer_dict_encode(s) + '\n'
print(result)
