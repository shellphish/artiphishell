from glob import glob

import json
import yaml

'''
{
    'method': method.dump_json() if method else None,
    'decision': self.decision,
    'llm_data': self.llm_data,
    'vuln': {
        'vuln_description': self.vuln_description,
        'vuln_function': self.vuln_function,
        'vuln_line': self.vuln_line,
        'vuln_code_line': self.vuln_code_line,
        'vuln_source': self.vuln_source,
        'vuln_type': self.vuln_type,
        'vuln_file': self.vuln_file,
    }
}
'''

def illmutable_file_parser_and_poi_dump(illmutable_dir, poi_dir, target):
    print(f'Starting iLLMutable POI dump for {illmutable_dir}...')
    count = 0
    audit_files = glob(f'{illmutable_dir}/*.json')
    for file in audit_files:
        print(f'Parsing {file}...')
        with open(file, 'r') as f:
            data_json = json.load(f)

        unsafe = data_json.get('unsafe',[])
        print(f'Results: {json.dumps(unsafe, indent=4)}')

        for item in unsafe:
            vuln = item.get('vuln', {})
            _temp = {
                'target': target,
                'scanner': 'illmutable',
                'vuln_description': vuln.get('vuln_description'),
                'vuln_function': vuln.get('vuln_function'),
                'vuln_line': vuln.get('vuln_line'),
                'vuln_code_line': vuln.get('vuln_code_line'),
                'vuln_source': vuln.get('vuln_source'),
                'vuln_type': vuln.get('vuln_type'),
                'vuln_file': vuln.get('vuln_file'),
            }
            path = f'{poi_dir}/illmutable-{count}.yaml'
            print(f'Dumping POI to {path}...')
            
            with open(path, 'w', encoding='utf-8') as poi_file:
                yaml.dump(_temp, poi_file, default_flow_style=False)
                count += 1
            with open(path, 'r') as poi_file:
                print(f'\n\n ========================\nPOI: {poi_file.read()}')
