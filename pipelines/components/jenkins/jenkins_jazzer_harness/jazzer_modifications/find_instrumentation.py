import argparse
import json
import yaml
import os
from collections import defaultdict

def write_to_txt_file(file_path, data):
    # Dump the list of packages in scope to the output file
    with open(file_path, 'w') as f:
        for d in data:
            f.write(f'"{d}"\n')


def parse_report_strings(keys):

    # for finding classes in scope from the function indexer report
    # Extract the last part after '::' from each key
    pats = list(map(lambda x: x.split('::')[-1], keys))

    # Extract the first part before the space from each element in pats
    val = list(map(lambda x: x.split(' ')[0], pats))

    # Split each element in val by '.' and join all but the last part with '.'
    classes_in_scope_per_antlr = set(map(lambda x: '/'.join(x.split('.')[:-1]), val))

    packages = []
    for class_name in classes_in_scope_per_antlr:
        split_name = class_name.split('/')
        if len(split_name) < 2:
            package_name = '.'.join(split_name)
            continue
        package_name = '.'.join(split_name[:-1])
        packages.append(package_name)

    return packages


def find_classes(func_report_path):

    # Read function indexer report
    with open(func_report_path, 'r') as f:
        func_report = json.load(f)
    keys = func_report.keys()

    packages = parse_report_strings(keys)
    sources_to_function_indices, sources_to_classes = defaultdict(list), defaultdict(list)

    # for each source
    for f_index, src in func_report.items():
        only_src_name = src.split('/')[0]
        sources_to_function_indices[only_src_name].append(f_index)

    for src, fi in sources_to_function_indices.items():
        tmp_results = parse_report_strings(fi)
        sources_to_classes[src] = ':'.join([f"{item}.**" for item in set(tmp_results)])
    return packages, sources_to_classes

# Function to clean and filter strings
def clean_and_filter_strings(strings):
    cleaned_strings = []
    for s in strings:
        print(s)
        if isinstance(s, str):
            cleaned = s.replace('\n', '').replace('\u0000', '')
            if len(cleaned) > 0:
                cleaned_strings.append(cleaned)
    return cleaned_strings


def use_reachability_report(report_path):

    dict_strings, reachable_files =  [], []
    
    # yaml safe load
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            data = yaml.safe_load(f)
        if data:
            java_string_literals = data.get('java-string-literals', {}).get('#select', {}).get('tuples', [])
            dict_strings = clean_and_filter_strings([item[0] for item in java_string_literals])

            # reaching functions 
            java_reaching_funcs = data.get('java_reaching_funcs', {}).get('#select', {}).get('tuples', [])
            tmp_reachable_files = clean_and_filter_strings([item[0] for item in java_reaching_funcs])
            
            for item in tmp_reachable_files:
                if item.startswith('<anonymous'):
                    continue
                item = '.'.join(item.split('.')[:-2])
                reachable_files.append(item)
   
    return dict_strings, list(set(reachable_files))
    

def main(args):

    if 'func_report' in args:
        func_report_path = args.func_report

    in_scope_packages_from_antlr, all_packages_from_reachability_report  = [], []
    in_scope_packages_from_antlr, sources_to_classes = find_classes(func_report_path)

    # codeql reports
    jazzer_strings = ["jaz.Zer", "jaz.Ter", "jazze", "jazzer", "..", "../", "../../", "../../../", "/",
                     "jazzer-traversal", "JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME", "jazzer.example.com", 
                     "JAZZER_SSR", "JAZZER_FILE_READ_WRITE", "JAZZER_COMMAND_INJECTION"]

    if 'reachability_report' in args:
        reachability_report = args.reachability_report
        dict_strings, all_packages_from_reachability_report = use_reachability_report(reachability_report)
        final_dict_strings = dict_strings + jazzer_strings
    else:
        final_dict_strings = jazzer_strings

    write_to_txt_file('dict.txt', final_dict_strings)
    # Combine the packages from the function indexer report and the reachability report
    data = {
        'in_scope_packages_from_antlr': ':'.join([f"{item}.**" for item in in_scope_packages_from_antlr]) ,
        'all_packages_from_reachability_report': ':'.join([f"{item}.**" for item in all_packages_from_reachability_report]),
        'sources_to_classes': sources_to_classes
    }

    if 'packages_in_scope' in args:
        packages_in_scope = args.packages_in_scope

    with open(packages_in_scope, 'w') as f:
        f.write(json.dumps(data))

if __name__ == "__main__":

    # Set up argument parser
    parser = argparse.ArgumentParser(description='Process Function indexer report and extract classes in scope.')
    parser.add_argument('--func_report', type=str, help='Path to the Function indexer report JSON file')
    parser.add_argument('--packages_in_scope', type=str, help='Path to the output file json file')
    parser.add_argument('--reachability_report', type=str, help='Path to the reachability report JSON file')

    args = parser.parse_args()
    assert args.func_report is not None, "Please provide the path to the Function indexer report JSON file"
    assert args.packages_in_scope is not None, "Please provide the path to the output json file where classes in scope will be saved"
    main(args)

