import os
from ast import literal_eval

import pandas as pd
import yaml


#######################################
#              mango                  #
#######################################


def mango_file_parser(mango_file_path):
    mongo = open(os.path.join(mango_file_path, 'traces.json'), 'r').read()
    literal = literal_eval(mongo)

    data = []
    for path in literal:

        sink = path[-1]

        sink_function = sink[-1]
        sink_line = sink[1]
        sink_file = sink[0]

        message_list = []
        for message_content in path:
            message_list.append(
                f'file:"{message_content[0]}" line:"{message_content[1]}" function:"{message_content[-1]}"')

        data.append({
            'uri': sink_file,
            'startLine': sink_line,
            'function': sink_function,
            'message': '\n'.join(message_list)
        })

    final = pd.DataFrame(data)
    return final


def mango_poi_dump(mango_db, poi_dir, target):
    count = 0
    for index, row in mango_db.iterrows():
        data = {
            'target': target,
            'scanner': 'mango',
            'vuln_source': 'static analysis',
            'vuln_function': row['function'],
            'vuln_description': row['message'],
            'vuln_line': int(row['startLine'])
        }
        with open(f'{poi_dir}/mango-{count}.yaml', 'w', encoding='utf-8') as file:
            yaml.dump(data, file, default_flow_style=False)
        count += 1
