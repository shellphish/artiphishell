import json
from glob import glob

import pandas as pd


######################################
#         jorn db sync               #
######################################

def compile_joern_data_base(joern_data_base_dir):
    _files_FUNCTION = glob(f'{joern_data_base_dir}/FUNCTION/*.json')
    _files_METHOD = glob(f'{joern_data_base_dir}/METHOD/*.json')
    _files_MACRO = glob(f'{joern_data_base_dir}/MACRO/*.json')
    _files = _files_MACRO + _files_METHOD + _files_FUNCTION
    _df = []
    for file_path in _files:
        data = json.load(open(file_path, 'r'))
        # Ugly hack to fix the broken json
        # data = eval(open(file_path, 'r').read())
        funcname = data['funcname']
        filename = data['filename']
        path_split = data['filename'].split('/')
        pkg = "src"
        file = ""
        if len(path_split) == 1:
            file = path_split[0]
        else:
            pkg, file = path_split[-2:]
        code = data['code']
        startline, endline = data['lines']
        count = startline
        line_map = []
        for i in code.split('\n'):
            line_map.append((count, i))
            count += 1
        _df.append({
            'funcname': funcname,
            'filename': filename,
            'startline': startline,
            'startLine': endline,
            'line_map': line_map,
            'code': code,
            'pkg': pkg,
            'file': file,
            'range': list(range(startline, endline + 1))
        })
    #         if endline !=count-1:
    #             raise Exception(f"Error: Joern code data is broken from line {count-1}")
    if len(_df) == 0: pd.DataFrame()
    return pd.DataFrame(_df)


def _cast(input):
    if len(input) == 1:
        return input[0][1]


def find_function(joern, db):
    has_code_flow = "code_flow" in db.columns()
    if joern.empty:
        temp_df = []
        for index, row in db.iterrows():
            temp_df.append({
                'vuln_level': row.level,
                'vuln_line': row.startLine,
                'vuln_function': -1,
                'vuln_code_line': -1,
                'vuln_file': row.uri,
                'vuln_description': row.message,
                'vuln_rule': row.rule_id,
                'vuln_rule_description': row.fullDescription,
                'vuln_code_flow': row.code_flow if has_code_flow else []
            })

        return pd.DataFrame(temp_df)
    else:
        temp_df = []
        for index, row in db.iterrows():
            file = row.file
            pkg = row.pkg
            _temp = joern.loc[(joern.file == file) & (joern.pkg == pkg)]
            for _index, _row in _temp.iterrows():
                if row.startLine in list(_row.range):
                    temp_df.append({
                        'vuln_level': row.level,
                        'vuln_line': row.startLine,
                        'vuln_function': _row.funcname,
                        'vuln_code_line': _cast(list(filter(lambda x: x[0] == row.startLine, _row.line_map))),
                        'vuln_file': row.uri,
                        'vuln_description': row.message,
                        'vuln_rule': row.rule_id,
                        'vuln_rule_description': row.fullDescription,
                        'vuln_code_flow': row.code_flow if has_code_flow else []
                    })
        return pd.DataFrame(temp_df)
