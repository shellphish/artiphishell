import argparse
import os
import time
import yaml

from collections import defaultdict

THRESHOLD = 0.5
MAX_SIMILAR = 50
MIN_SIMILAR = 1

BLACKLIST_STARTSWITH = {"LLVM",}

def main(benign_inputs, benign_coverages, poi_report_at, output_dir):
    with open(poi_report_at) as f:
        poi_report = yaml.safe_load(f)
    crashing_covered_funcs = set()
    print(f"Crashing covered functions:")
    for stack_trace in poi_report['stack_traces']:
        for call_loc in stack_trace['call_locations']:
            # only fetch functions in the main binary (not libraries) and not blacklisted
            if call_loc['key_index'] is not None and 'function_name' not in call_loc.keys():
                try:
                    # then we parse the function
                    call_loc['function_name'] = call_loc['function'].split('(')[0].split(' ')[-1]
                except:
                    continue
            
            if call_loc['key_index'] is not None and not any(call_loc['function_name'].startswith(blacklist) for blacklist in BLACKLIST_STARTSWITH):
                crashing_covered_funcs.add(call_loc['function_name'])
                print(f"\t{call_loc['function_name']}")

    similar_funcs = defaultdict(list)
    
    for basename in os.listdir(benign_coverages):
        print(f"Checking {basename}")

        benign_covered_funcs = set()
        with open(f"{benign_coverages}/{basename}", 'r') as f:
            for line in f:
                line = line.strip()
                if not any(line.startswith(blacklist) for blacklist in BLACKLIST_STARTSWITH):
                    benign_covered_funcs.add(line)
        
        percentage_similar_funcs = len(benign_covered_funcs & crashing_covered_funcs) / len(crashing_covered_funcs) * 100

        if percentage_similar_funcs > THRESHOLD:
            print(f"{basename}: {percentage_similar_funcs:.2f}% similar functions")
            similar_funcs[percentage_similar_funcs].append(basename)
        else:
            print(f"{basename}: {percentage_similar_funcs:.2f}% similar functions (not enough)")

    # abort if we don't have any/enough similar seeds
    num_available_similar = len({basename for similar_list in similar_funcs.values() for basename in similar_list})
    assert num_available_similar >= MIN_SIMILAR, f"{num_available_similar} < {MIN_SIMILAR} minimum similar seeds available, aborting"

    # else copy the top MAX_SIMILAR similar seeds
    counter = 0
    for similarity in sorted(similar_funcs.keys(), reverse=True):
        for basename in similar_funcs[similarity]:
            counter += 1
            print(f'Copying {basename} to {output_dir}/{basename}')
            os.system(f"cp {benign_inputs}/{basename} {output_dir}/{basename}")
            if counter >= MAX_SIMILAR:
                return
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find similar seeds')

    parser.add_argument('--benign_inputs', type=str, required=True, help='Path to benign inputs')
    parser.add_argument('--benign_coverages', type=str, required=True, help='Path to benign coverages')
    parser.add_argument('--poi_report_at', type=str, required=True, help='Path to poi report')
    parser.add_argument('--output_dir', type=str, required=True, help='Path to output directory')

    args = parser.parse_args()

    for _ in range(5):
        try:
            main(args.benign_inputs, args.benign_coverages, args.poi_report_at, args.output_dir)
            break
        except Exception as e:
            print(f"Error: {e}")
            print("Retrying in 2 minutes...")
            time.sleep(120)
    else:
        # TODO: maybe dump empty similar directory?
        raise Exception("Failed to find similar seeds")
