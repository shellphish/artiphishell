import pandas as pd
import pysarif
import yaml


#######################################
#               snyk                #
#######################################


def snyk_sarif_parser(snyk_file_path):
    snyk_file = pysarif.load_from_file(snyk_file_path)
    findings = snyk_file.to_dict()

    data = []
    scan_list = []

    for run in findings['runs']:
        for scan_query in run['tool']['driver']['rules']:
            full_desc_field = scan_query.get('fullDescription', None) or scan_query.get('help', {})
            full_description = full_desc_field.get('markdown', None) or full_desc_field.get('text', None)
            scan_list.append({
                'rule_id': scan_query['id'],
                'level_of_rule': scan_query['defaultConfiguration']['level'],
                'fullDescription': full_desc_field
            })

    for run in findings['runs']:
        for result in run['results']:
            for location in result['locations']:
                startline = location['physicalLocation']['region']['startLine']
                uri = location['physicalLocation']['artifactLocation']['uri']
                path_split = uri.split('/')
                pkg = "src"
                file = ""
                if len(path_split) == 1:
                    file = path_split[0]
                else:
                    pkg, file = path_split[-2:]
                _temp = {
                    'message': result['message']['text'],
                    'level': result['level'],
                    'rule_id': result['ruleId'],
                    'uri': uri,
                    'startLine': startline,
                    'endLine': location['physicalLocation']['region']['endLine'],
                    'pkg': pkg,
                    'file': file
                }
                data.append(_temp)

    rule = pd.DataFrame(scan_list)
    if len(data) == 0:
        df =  pd.DataFrame({
            'message': [],
            'level': [],
            'rule_id': [],
            'uri': [],
            'startLine': [],
            'endLine': [],
            'pkg': [],
            'file': []
        }, index=[])
        final = pd.merge(df, rule, on='rule_id', how='left')
        return final
    else:
        df = pd.DataFrame(data)
        final = pd.merge(df, rule, on='rule_id', how='left')
        return final


def snyk_poi_dump(snyk_db, poi_dir, target):
    count = 0
    for index, row in snyk_db.iterrows():
        data = {
            'target': target,
            'scanner': 'snyk',
            'vuln_source': 'static analysis',
            'vuln_level': row.vuln_level,
            'vuln_line': row.vuln_line,
            'vuln_function': row.vuln_function,
            'vuln_code_line': row.vuln_code_line,
            'vuln_file': row.vuln_file,
            'vuln_description': row.vuln_description,
            'vuln_rule': row.vuln_rule,
            'vuln_rule_description': row.vuln_rule_description
        }
        with open(f'{poi_dir}/snyk-{count}.yaml', 'w', encoding='utf-8') as file:
            yaml.dump(data, file, default_flow_style=False)
        count += 1
