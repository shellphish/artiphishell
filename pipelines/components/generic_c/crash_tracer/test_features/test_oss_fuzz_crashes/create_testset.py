import csv
import hashlib
import os
import shutil
import pandas as pd

import tqdm
import yaml


reader = pd.read_csv('ossfuzz_crash_reports.csv')

shutil.rmtree('test_run_pov_results/', ignore_errors=True)
shutil.rmtree('test_reports/', ignore_errors=True)
os.makedirs('test_run_pov_results/', exist_ok=True)
os.makedirs('test_reports', exist_ok=True)
for i, row in tqdm.tqdm(list(reader.iterrows())):
    # print(row.keys())
    row['Report'] = row['Report'].encode()
    row['Project'] = eval(row['Project'])
    # print(row['Project'], row['Report'])

    h = hashlib.sha256(row['Report']).hexdigest()

    run_pov_result = {
        'target_id': 1,
        'harness_info_id': 1,
        'crash_report_id': 1,
        'cp_harness_id': 1,
        'cp_harness_name': 'a',
        'cp_harness_binary_path': 'out/asdf',
        'cp_harness_source_path': 'asdf',
        'fuzzer': 'aflplusplus',
        'run_pov_result': {
            'stdout': b'',
            'stderr': row['Report'],
        }
    }

    out_file = f'test_run_pov_results/{row["Project"]}_{h}.yaml'
    with open(out_file, 'w') as out:
        yaml.safe_dump(run_pov_result, out)

    with open(f'test_reports/{row["Project"]}_{h}.txt', 'wb') as out:
        out.write(row['Report'])