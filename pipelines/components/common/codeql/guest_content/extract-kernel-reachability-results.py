import json
import os
import sys

import yaml

# load merged codeql_results.json
with open(sys.argv[1], 'r') as f:
    data = yaml.safe_load(f)

result_reachability = {}

assert data['kernel_reaching_files']['#select']['columns'] == [{'kind': 'String'}]
reaching_files = [os.path.join('src', v[0]) for v in data['kernel_reaching_files']['#select']['tuples']]

assert data['kernel_reaching_syscalls']['#select']['columns'] == [{'kind': 'String'}]
reaching_syscalls = [v[0] for v in data['kernel_reaching_syscalls']['#select']['tuples']]

with open(sys.argv[2], 'w') as f:
    json.dump({
        'target_id': sys.argv[3],
        'syscalls': reaching_syscalls,
        'files': reaching_files,
        'functions': [],
    }, f)
