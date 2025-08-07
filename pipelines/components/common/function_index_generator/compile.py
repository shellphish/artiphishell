import argparse  # Import argparse module for command-line parsing
import functools
import json
import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from glob import glob
from multiprocessing import Pool, cpu_count

import dask.dataframe as dd
import pandas as pd
from tqdm import tqdm

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def process_file_for_meta_index(file_path, functions_by_file_json_path=None):
    with open(file_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            f.seek(0)
            print(f.read())
            raise e
    funcname = data['funcname']
    filename = data['filename']
    filepath = data['filepath']
    start_line = data['start_line']
    start_column = data['start_column']
    end_line = data['end_line']
    end_column = data['end_column']
    start_offset = data['start_offset']
    end_offset = data['end_offset']
    function_signature = f"{filepath}:{start_line}:{start_column}::{data['signature']}"

    # startcolumn = data['startcolumn']
    # endcolumn = data['endcolumn']
    code = data['code']
    line_map = [(start_line + i, line) for i, line in enumerate(code.split('\n'))]
    meta_index = {
        'func_name': funcname,
        'function_signature': function_signature,
        'filename': filename,
        'filepath': filepath,
        'start_line': start_line,
        'end_line': end_line,
        'start_column': start_column,
        'end_column': end_column,
        'start_offset': start_offset,
        'end_offset': end_offset,
        'line_map': line_map,
    }
    if not functions_by_file_json_path:
        return meta_index

    by_file = (filepath, {
        'start_line': start_line,
        'start_column': start_column,
        'start_offset': start_offset,
        'end_line': end_line,
        'end_column': end_column,
        'end_offset': end_offset,
        'function_signature': function_signature
    })
    return meta_index, by_file


def process_file_for_index(input_dir, file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    index = dict()
    filepath = data['filepath']
    function_signature = f"{filepath}:{data['start_line']}:{data['start_column']}::{data['signature']}"
    index[function_signature] = os.path.relpath(file_path, input_dir)
    return index


def merge_dicts(dicts):
    result = {}
    for dictionary in dicts:
        result.update(dictionary)
    return result


def parallel_merge_dicts(all_dicts, chunk_size):
    chunks = [all_dicts[i:i + chunk_size] for i in range(0, len(all_dicts), chunk_size)]
    with ThreadPoolExecutor() as executor:
        intermediate_results = list(executor.map(merge_dicts, chunks))
    final_result = {}
    for intermediate in intermediate_results:
        final_result.update(intermediate)
    return final_result


def compile_code_db(run_mode, input_dir, output_meta_index_csv, target_function_index,
                    functions_by_file_json_path=None):
    if run_mode == 'commit':
        DATA = {}
        for project in glob(f'{input_dir}/*'):
            commit_dirs = glob(f'{project}/*')
            data = {}
            for commit in commit_dirs:
                files = set(glob(f'{commit}/**/*.json', recursive=True))
                num_cpus = cpu_count()
                chunk_size = min(512, (len(files) // num_cpus) + 1)
                logging.info(f'Number of CPUs used: {num_cpus}, Chunk size: {chunk_size}')
                with Pool(processes=num_cpus) as pool:
                    results_index = list(
                        tqdm(pool.imap_unordered(functools.partial(process_file_for_index, input_dir), files,
                                                 chunksize=chunk_size),
                             total=len(files)))
                data[os.path.basename(commit)] = results_index
            transformed_dict = {k: {k2: v2 for d in v for k2, v2 in d.items()} for k, v in data.items()}
            DATA[os.path.basename(project)] = transformed_dict
        with open(target_function_index, 'w') as f:
            logging.info('Writing index to JSON')
            json.dump(DATA, f)
            logging.info('Index written to JSON successfully')
        return 0

    logging.info(f'Compiling code database for directory: {input_dir}')
    files = glob(f'{input_dir}/**/*.json', recursive=True)
    num_cpus = cpu_count()
    chunk_size = min(512, (len(files) // num_cpus) + 1)
    logging.info(f'Number of CPUs used: {num_cpus}, Chunk size: {chunk_size}')

    with Pool(processes=num_cpus) as pool:
        results_meta_index = list(tqdm(pool.imap_unordered(
            functools.partial(process_file_for_meta_index, functions_by_file_json_path=functions_by_file_json_path),
            files,
            chunksize=chunk_size,
        ),
            total=len(files)
        ))

    with Pool(processes=num_cpus) as pool:
        results_index = list(
            tqdm(pool.imap_unordered(functools.partial(process_file_for_index, input_dir), files, chunksize=chunk_size),
                 total=len(files)))

    # results_meta_index is a list of tuples, split it out
    if functions_by_file_json_path:
        results_meta_index, results_source_index = zip(*results_meta_index)
        source_index = defaultdict(list)
        for filepath, source_data in results_source_index:
            source_index[filepath].append(source_data)
        with open(functions_by_file_json_path, 'w') as f:
            json.dump(dict(source_index), f)

    combined_dict = parallel_merge_dicts(results_index, chunk_size)

    df = pd.DataFrame(results_meta_index)
    ddf = dd.from_pandas(df, npartitions=max(num_cpus, len(results_meta_index) // 1000))
    logging.info('Writing DataFrame to CSV')
    ddf.to_csv(output_meta_index_csv, index=False, single_file=True)
    logging.info('DataFrame written to CSV successfully')

    with open(target_function_index, 'w') as f:
        logging.info('Writing index to JSON')
        json.dump(combined_dict, f)
        logging.info('Index written to JSON successfully')

    return 0


ARGS = None


def main():
    global ARGS
    parser = argparse.ArgumentParser(description="Compile a code database from JSON files.")
    parser.add_argument('--mode', type=str, required=True, help='Mode of compilation full or commit')
    parser.add_argument('--input-target-functions-json-dir', type=str, required=True,
                        help='Input directory containing JSON files')
    parser.add_argument('--output-meta-index-csv', type=str, required=True, help='Output path for meta-index csv')
    parser.add_argument('--output-target-functions-index', required=True, type=str,
                        help='Output path for target functions index')
    parser.add_argument('--output-functions-by-file-index-json', required=False, type=str, default=None,
                        help='Output path for source index JSON')
    ARGS = parser.parse_args()

    assert ARGS.mode in ['full', 'commit'], 'Mode must be either full or commit'

    if 'output_functions_by_file_index_json' in ARGS:
        output_functions_by_file_index_json = ARGS.output_functions_by_file_index_json
    else:
        output_functions_by_file_index_json = None

    compile_code_db(
        run_mode=ARGS.mode,
        input_dir=ARGS.input_target_functions_json_dir,
        output_meta_index_csv=ARGS.output_meta_index_csv,
        target_function_index=ARGS.output_target_functions_index,
        functions_by_file_json_path=output_functions_by_file_index_json
    )


if __name__ == "__main__":
    main()
