import argparse
import os
import yaml
import sys

# EXAMPLE YAML FILE
'''
generic_c_reaching_files:
  '#select':
    columns:
    - kind: String
    tuples:
    - - src/event/ngx_event_openssl.c
    - - src/event/ngx_event_openssl_stapling.c
    - - src/http/ngx_http_core_module.c
    - - src/http/modules/ngx_http_memcached_module.c
    - - src/event/ngx_event_pipe.c
generic_c_reaching_functions:
  '#select':
    columns:
    - kind: String
    tuples:
    - - ngx_chain_writer
    - - ngx_output_chain
    - - ngx_resolve_name
    - - ngx_ssl_send_chain
    - - ngx_ssl_recv_chain
'''

parser = argparse.ArgumentParser(description='Extract the coverage filters from the reachability results of the fuzzer')
parser.add_argument('extraction_results_yaml_path', type=str, help='Path to the extraction results yaml file')
parser.add_argument('only_functions_coverage_filter_path', type=str, help='Path to the output file for the only functions coverage filter')
parser.add_argument('only_files_coverage_filter_path', type=str, help='Path to the output file for the only files coverage filter')
args = parser.parse_args()

extraction_results_path = args.extraction_results_yaml_path
with open(extraction_results_path, 'r') as f:
    extraction_results = yaml.safe_load(f)

# Extract the list of files that are reached by the fuzzer
assert extraction_results['generic_c_reaching_files']['#select']['columns'] == [{'kind': 'String'}]
reached_files = ['src:'+os.path.join('*', tup[0]) for tup in extraction_results['generic_c_reaching_files']['#select']['tuples']]

assert extraction_results['generic_c_reaching_functions']['#select']['columns'] == [{'kind': 'String'}]
reached_functions = ['fun:'+tup[0] for tup in extraction_results['generic_c_reaching_functions']['#select']['tuples']]

with open(args.only_files_coverage_filter_path, 'w') as f:
    f.write('\n'.join(reached_files + reached_functions))
    
with open(args.only_functions_coverage_filter_path, 'w') as f:
    f.write('\n'.join(reached_functions))