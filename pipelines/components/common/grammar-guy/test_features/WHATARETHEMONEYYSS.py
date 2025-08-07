import pandas as pd
import argparse
import pathlib
import json 
import os 
import os
import yaml

# reading all the cost entrys and storing them in df for easy calculation
def read_cost_files(directory):
    assert(os.path.exists(directory))
    completion_cost = []
    prompt_cost = []
    total_cost = []
    time_list = []
    files = os.listdir(directory)
    print(f"Len of files in dir {len(files)}")
    files.sort()
    for file in files:
        with open(os.path.join(directory, file), "r") as f:
            data = yaml.safe_load(f)
            if "cost" in data.keys():
                completion_cost.append(data["cost"]["completion_cost"])
                prompt_cost.append(data["cost"]["prompt_cost"])
                total_cost.append(data["cost"]["total_cost"])
    return completion_cost, prompt_cost, total_cost

# sorting and reading all the events. should be in order? 
def read_event_files(directory):
    assert(os.path.exists(directory))
    events_in_order = []
    files = os.listdir(directory)
    print(f"Len of files in dir {len(files)}")
    # sort files in folder by name
    files.sort()
    # sort files by "time" key in yaml
    files.sort(key=lambda x: get_time_from_yaml(os.path.join(directory, x)))
    for file in files:
        with open(os.path.join(directory, file), "r") as f:
            data = yaml.safe_load(f)
            if "event" in data.keys():
                events_in_order.append(data["event"])
    return events_in_order

def get_time_from_yaml(file_path):
    with open(file_path, "r") as f:
        data = yaml.safe_load(f)
        if "time" in data.keys():
            return data["time"]
        else:
            return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # parser.add_argument("--filepath", type=str, help="The directory to store the stats", default="/home/zebck/Documents/aixcc/shellphish-crs/pipelines/components/common/grammar-guy/test_features/challenge-004-nginx-cp/backup/grammar_guy_fuzz.events_dir")
    parser.add_argument("-f", "--filepath", type=str, help="The directory to store the stats", default="/home/zebck/Documents/aixcc/shellphish-crs/pipelines/components/common/grammar-guy/test_features/challenge-004-nginx-cp/backup/grammar_guy_fuzz.events_dir/")
    args = parser.parse_args()
    # Parse files and create dataframe for eval
    completion_cost, prompt_cost, total_cost = read_cost_files(args.filepath)
    events_in_order = read_event_files(args.filepath)
    
    df = pd.DataFrame({'cost_list': completion_cost, 'prompt_cost': prompt_cost, 'total_cost': total_cost})
    print("The total cost of doing the things that were done is: ", df['total_cost'].sum())
    print("All the events that were done in order are:",)
    for i in events_in_order:
        print(i)