import pandas as pd
import pysarif
import yaml


#######################################
#               codeql                #
#######################################

def _get_code_flows(result: dict) -> list[list[dict]]:
    if "codeFlows" not in result or result["codeFlows"] is None:
        return []

    code_flows = []
    for code_flow in result["codeFlows"]:
        for thread_flow in code_flow["threadFlows"]:
            curr_thread_flow = []
            for location_outer in thread_flow["locations"]:
                location = location_outer["location"]
                if "physicalLocation" in location:
                    physical_location = location["physicalLocation"]
                    _entry = {
                        "uri": physical_location["artifactLocation"]["uri"],
                        "startLine": physical_location["region"]["startLine"],
                        "startColumn": physical_location["region"]["startColumn"],
                        "endColumn": physical_location["region"]["endColumn"],
                        "message": location["message"]["text"]
                    }
                    curr_thread_flow.append(_entry)
            code_flows.append(curr_thread_flow)
    return code_flows

def code_ql_sarif_parser(codeql_file_path):
    codeql_file = pysarif.load_from_file(codeql_file_path)
    findings = codeql_file.to_dict()

    data = []
    scan_list = []

    for run in findings['runs']:
        for scan_query in run['tool']['driver']['rules']:
            scan_list.append({
                'rule_id': scan_query['id'],
                'level_of_rule': scan_query['defaultConfiguration']['level'],
                'fullDescription': scan_query['fullDescription']['text']
            })

    for run in findings['runs']:
        for result in run['results']:
            code_flows = _get_code_flows(result)
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

                # just creating multiple records (one for each flow trace)
                if code_flows:
                    for code_flow in code_flows:
                        _temp = {
                            'message': result['message']['text'],
                            'level': result['level'],
                            'rule_id': result['rule']['id'],
                            'uri': uri,
                            'startLine': startline,
                            'endLine': location['physicalLocation']['region']['endLine'],
                            'pkg': pkg,
                            'file': file,
                            'code_flow': code_flow
                        }
                        data.append(_temp)
                else:
                    _temp = {
                        'message': result['message']['text'],
                        'level': result['level'],
                        'rule_id': result['rule']['id'],
                        'uri': uri,
                        'startLine': startline,
                        'endLine': location['physicalLocation']['region']['endLine'],
                        'pkg': pkg,
                        'file': file,
                        'code_flow': []
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
            'file': [],
            'code_flow': []
        }, index=[])
        final = pd.merge(df, rule, on='rule_id', how='left')
        return final
    else:
        df = pd.DataFrame(data)
        final = pd.merge(df, rule, on='rule_id', how='left')
        return final


def code_ql_poi_dump(codeql_db, poi_dir, target):
    count = 0
    for index, row in codeql_db.iterrows():
        data = {
            'target': target,
            'scanner': 'codeql',
            'vuln_source': 'static analysis',
            'vuln_level': row.vuln_level,
            'vuln_line': row.vuln_line,
            'vuln_function': row.vuln_function,
            'vuln_code_line': row.vuln_code_line,
            'vuln_file': row.vuln_file,
            'vuln_description': row.vuln_description,
            'vuln_rule': row.vuln_rule,
            'vuln_rule_description': row.vuln_rule_description,
            'vuln_code_flow': row.vuln_code_flow
        }
        with open(f'{poi_dir}/codeql-{count}.yaml', 'w', encoding='utf-8') as file:
            yaml.dump(data, file, default_flow_style=False)
            count += 1
