from glob import glob

import yaml


def opwnaiaudit_file_parser_and_poi_dump(opwnaiaudit_dir, poi_dir, target):
    count = 0
    audit_files = glob(f'{opwnaiaudit_dir}/*.yml')
    for file in audit_files:
        data_file = open(file, 'r').read()
        data_yaml = yaml.load(data_file, Loader=yaml.FullLoader)
        _temp = {
            'target': target,
            'scanner': 'opwnaiaudit',
            'vuln_description': data_yaml['vuln_description'],
            'vuln_function': data_yaml['vuln_function'],
            'vuln_line': data_yaml['vuln_line'],
            'vuln_source': data_yaml['vuln_source'],
            'vuln_type': data_yaml['vuln_type'],
        }
        with open(f'{poi_dir}/opwnaiaudit-{count}.yaml', 'w', encoding='utf-8') as poi_file:
            yaml.dump(_temp, poi_file, default_flow_style=False)
            count += 1
