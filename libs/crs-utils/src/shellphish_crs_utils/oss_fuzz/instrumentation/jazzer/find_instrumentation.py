import argparse
import json
import yaml
import os
from collections import defaultdict

def write_to_txt_file(file_path, data):
    # Dump the list of packages in scope to the output file
    with open(file_path, 'w') as f:
        for d in data:
            # the encode already adds the quotes
            f.write(f'{d}\n')


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
        if '/' not in class_name:
            continue
        package_name = class_name.rsplit('/', 1)[0]
        if not package_name:
            continue
        packages.append(package_name.replace('/', '.'))

    return list(set(packages))


def find_classes(func_report_path):

    # Read function indexer report
    with open(func_report_path, 'r') as f:
        func_report = json.load(f)
    keys = func_report.keys()

    packages = parse_report_strings(keys)
    sources_to_function_indices = defaultdict(list)

    # for each source
    for f_index, src in func_report.items():
        only_src_name = src.split('/')[0]
        sources_to_function_indices[only_src_name].append(f_index)

    for src, fi in sources_to_function_indices.items():
        tmp_results = parse_report_strings(fi)
    return packages



def use_reachability_report(report_path):

    dict_strings, reachable_classes =  [], []
    if not report_path:
        return dict_strings, reachable_classes
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    for key, value in report.items():
        if key == "interesting_strings":
            dict_strings = value
        elif key == "java_reaching_classes":
            reachable_classes = value

    return dict_strings, reachable_classes

def main(args):

    func_report_path = args.func_report

    in_scope_packages_from_antlr, all_classes_from_reachability_report  = [], []
    in_scope_packages_from_antlr = find_classes(func_report_path)

    jazzer_strings = ["jaz.Zer", "jaz.Ter", "jazze", "jazzer", "..", "../", "jazzer-traversal", "JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME", "jazzer.example.com", 
                     "JAZZER_SSR", "JAZZER_FILE_READ_WRITE", "JAZZER_COMMAND_INJECTION"]

    if 'reachability_report' in args:
        reachability_report = args.reachability_report
        dict_strings, all_classes_from_reachability_report = use_reachability_report(reachability_report)
        final_dict_strings = dict_strings + jazzer_strings
    else:
        final_dict_strings = jazzer_strings
    # Lets make sure to write atleast fuzz to the string
    if len(final_dict_strings) < 1:
        final_dict_strings = ["fuzz"]

    # Now lets make sure that we encode the strings so that we don't have any parsing issues
    final_dict_set = set()
    for entry in final_dict_strings:
        hex_content = "".join(f"\\x{byte:02x}" for byte in entry.encode("utf-8"))
        final_dict_set.add(f'"{hex_content}"')
    final_dict_strings = list(final_dict_set)
    # Write the final dictionary to a file
    write_to_txt_file('/shellphish/dict.txt', final_dict_strings)
    # Combine the packages from the function indexer report and the reachability report
    # quick for april 1st. TODO : see if this can be improved
    data = {
        'in_scope_packages_from_antlr': chr(34) + ':'.join([f"{item}.**" for item in in_scope_packages_from_antlr]) + chr(34),
        'all_classes_from_reachability_report': chr(34)  + ':'.join([f"{item}.**" for item in all_classes_from_reachability_report]) + chr(34),
    }

    packages_in_scope = args.packages_in_scope

    with open(packages_in_scope, 'w') as f:
        f.write(json.dumps(data))

if __name__ == "__main__":

    # Set up argument parser
    parser = argparse.ArgumentParser(description='Process Function indexer report and extract classes in scope.')
    parser.add_argument('--func_report', type=str, help='Path to the Function indexer report JSON file', required=True)
    parser.add_argument('--packages_in_scope', type=str, help='Path to the output file json file', required=True)
    parser.add_argument('--reachability_report', type=str, default=None, help='Path to the reachability report JSON file')

    args = parser.parse_args()
    assert args.func_report is not None, "Please provide the path to the Function indexer report JSON file"
    assert args.packages_in_scope is not None, "Please provide the path to the output json file where classes in scope will be saved"
    main(args)