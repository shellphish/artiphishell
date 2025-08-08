from ruamel.yaml import YAML
import sys

budget = 30
if len(sys.argv) > 1:
    budget = int(sys.argv[1])

file = '../../../infra/litellm/proxy_server_config.yaml'
final = 'config.yaml'
prefix = 'litellm_proxy/'
openai_prefix = 'openai/'

output = {'model_list': [], 'litellm_settings': {'max_budget': budget}}
api_key = None
API_BASE = 'http://wiseau.seclab.cs.ucsb.edu:666'

def make_entry(model_name, double_proxy):
    return {
            'model_name': model_name,
            'litellm_params': {
                'model': double_proxy,
                'api_base': API_BASE,
                'api_key': api_key,
            }
        }
    

with open(file, 'r') as f:
    yaml = YAML()
    config = yaml.load(f)
    models = config.get('model_list', [])
    master_key = config.get('general_settings', {}).get('master_key', '')
    api_key = master_key

    for model in models:
        print(f"Processing model: {model}")
        need_name = model.get('model_name', '')
        proxy_name = model.get('litellm_params', {}).get('model', '')
        double_proxy = prefix + need_name

        output['model_list'].append(make_entry(need_name, double_proxy))
        output['model_list'].append(make_entry(proxy_name, double_proxy))
        output['model_list'].append(make_entry(openai_prefix + need_name, double_proxy))

with open(final, 'w') as f:
    yaml.dump(output, f)