import csv
import json
import argparse
import os
import pandas as pd

def csv_to_json(project_id, name, csv_file_path, json_file_path):
    # with open(csv_file_path, mode='r', newline='') as csv_file:
    #     csv_reader = csv.DictReader(csv_file)
    #     function_names = []
    #     for row in csv_reader:
    #         function_names.append(row['func_name'])

    # df = pd.DataFrame(results_meta_index)
    # ddf = dd.from_pandas(df, npartitions=max(num_cpus, len(results_meta_index) // 1000))
    # logging.info('Writing DataFrame to CSV')
    # ddf.to_csv(output_meta_index_csv, index=False, single_file=True)
    # logging.info('DataFrame written to CSV successfully')
    
    df = pd.read_csv(csv_file_path)
    function_names = df['func_name'].tolist()
    
    data = {
        'name': name,
        'project_id': project_id,
        'target_functions': function_names,
    }
    
    with open(json_file_path, mode='w') as json_file:
        json.dump(data, json_file, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Convert a CSV file to a JSON file.")
    parser.add_argument('--project-id', required=True, type=str, help='The project ID')
    parser.add_argument('--name', required=True, type=str, help='The name of the request')

    parser.add_argument('commit_index_json', type=str, help='Path to the commit index JSON file')
    parser.add_argument('commit_jsons_dir', type=str, help='Path to the directory containing the commit JSON files')
    parser.add_argument('out_reachability_request', type=str, help='Path to the output reachability request JSON file')

    args = parser.parse_args()

    with open(args.commit_index_json, mode='r') as json_file:
        commit_index = json.load(json_file)
    
    reachability_request = {
        'name': args.name,
        'project_id': args.project_id,
        'target_functions': [],
        'target_function_keys': [],
        'target_functions_by_commit': {},
        'target_function_keys_by_commit': {},
    }
    for source, by_commit in commit_index.items():
        for commit, by_function in by_commit.items():
            reachability_request['target_functions_by_commit'][commit] = []
            reachability_request['target_function_keys_by_commit'][commit] = []
            for func_key, func_path in by_function.items():
                with open(os.path.join(args.commit_jsons_dir, func_path), mode='r') as json_file:
                    funcname = json.load(json_file)['funcname']
                    reachability_request['target_functions'].append(funcname)
                    reachability_request['target_functions_by_commit'][commit].append(funcname)
                reachability_request['target_function_keys'].append(func_key)
                reachability_request['target_function_keys_by_commit'][commit].append(func_key)

    with open(args.out_reachability_request, mode='w') as json_file:
        json.dump(reachability_request, json_file, indent=2)

if __name__ == "__main__":
    main()
