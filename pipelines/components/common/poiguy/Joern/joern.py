import os
from ast import literal_eval

import pandas as pd
import yaml


#######################################
#              joern                  #
#######################################


def joern_file_parser(joern_file_path):
    with open(os.path.join(joern_file_path, 'TEST'), 'r', encoding='utf-8') as f:
        # Query Score |	Query Title	 | Filepath | 	Line Number  | Function Name
        return pd.DataFrame(literal_eval(f.read()))



def joern_poi_dump(joern_db, poi_dir, target):
    count = 0
    for index, row in joern_db.iterrows():
        data = {
            'target': target,
            'scanner': 'joern',
            'vuln_source': 'static analysis',
            'vuln_function': row['Function Name'],
            'vuln_description': row['Query Title'],
            'vuln_line': row['Line Number']
        }
        with open(f'{poi_dir}/joern-{count}.yaml', 'w', encoding='utf-8') as file:
            yaml.dump(data, file, default_flow_style=False)
        count += 1
