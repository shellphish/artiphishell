from ast import literal_eval

import pandas as pd
import yaml


def ddfa_file_parser(ddfa_file_path):
    ddfa_data = open(ddfa_file_path, 'r').read()
    info = literal_eval(ddfa_data)
    data = []
    for row in info:
        data.append({
            'funcname': row['funcname'],
            'filename': row['filename'],
            'lines': row['lines'][0],
            'vulnerable_pred': row['vulnerable_pred']
        })

    final = pd.DataFrame(data)
    return final


def ddfa_poi_dump(ddfa_db, poi_dir, target):
    count = 0
    for index, row in ddfa_db.iterrows():
        data = {
            'target': target,
            'scanner': 'ddfa',
            'vuln_source': 'static analysis',
            'vuln_function': row['funcname'],
            'vuln_description': f"ddfa detected {row['vulnerable_pred']}",
            'vuln_line': int(row['lines']),
            'vuln_file': row['filename']
        }
        with open(f'{poi_dir}/ddfa-{count}.yaml', 'w') as file:
            yaml.dump(data, file, default_flow_style=False)
            count += 1
