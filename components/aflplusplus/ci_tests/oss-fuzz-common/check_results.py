from collections import defaultdict
import json
import subprocess
import os
import sys

import yaml

TARGET_NAME = sys.argv[1]
DURATION = sys.argv[2]
print('''<details>

<summary>pd status results ... </summary>
<pre>''')
data = json.load(sys.stdin)
print(json.dumps(data, indent=2))
print("</pre>")
print("</details>")
print("Checking results ... ")


def get_logs(task,job):
    try:
        print(f'''<details>

<summary>pd cat {task} {job} ... </summary>
<pre>''')
        res = subprocess.check_output(["pd", "cat", task, job],timeout=60)
        if type(res) == bytes:
            res = res.decode("latin1")
        print(res)
        print("</pre>")
        print("</details>")
    except Exception as e:
        print(f"Error: {e}")
        pass
# if (
#     data['aflpp_build_image']['success'][0] != ["1"]
#     or data['aflpp_build_image']['aflpp_image_ready'][0] != ["1"]
# ):
#     get_logs("aflpp_build_image.logs", "1")
# assert data['aflpp_build_image']['success'][0] == ["1"], f"aflpp image couldn't be built? {data['aflpp_build_image']}"
# assert data['aflpp_build_image']['aflpp_image_ready'][0] == ["1"], f"aflpp image couldn't be built? {data['aflpp_build_image']}"

if (
    data['aflpp_build']['success'][0] != ["1"]
    or data['aflpp_build']['aflpp_built_target'][0] != ["1"]
):
    get_logs("aflpp_build.logs", "1")
assert data['aflpp_build']['success'][0] == ["1"], f"aflpp target couldn't be built? {data['aflpp_build']}"
assert data['aflpp_build']['aflpp_built_target'][0] == ["1"], f"aflpp target couldn't be built? {data['aflpp_build']}"

# if (
#     data['aflpp_build_cmplog']['success'][0] != ["1"]
#     or data['aflpp_build_cmplog']['target_image'][0] != ["1"]
#     or data['aflpp_build_cmplog']['aflpp_cmplog_built_target'][0] != ["1"]
# ):
#     get_logs("aflpp_build_cmplog.logs", "1")
# assert data['aflpp_build_cmplog']['success'][0] == ["1"], f"aflpp target couldn't be built? {data['aflpp_build_cmplog']}"
# assert data['aflpp_build_cmplog']['target_image'][0] == ["1"], f"aflpp target couldn't be built? {data['aflpp_build_cmplog']}"
# assert data['aflpp_build_cmplog']['aflpp_cmplog_built_target'][0] == ["1"], f"aflpp target couldn't be built? {data['aflpp_build_cmplog']}"

assert data['aflpp_fuzz']['aflpp_built_target'][0] == ['1'], f"aflpp_target wasn't built? {data['aflpp_fuzz']}"
# assert data['aflpp_fuzz']['aflpp_cmplog_built_target'][0] == ['1'], f"aflpp_cmplog target wasn't built? {data['aflpp_fuzz']}"

assert data['aflpp_fuzz_merge']['aflpp_built_target'][0] == ['1'], f"aflpp_target wasn't built? {data['aflpp_fuzz_merge']}"

def get_benigns_per_harness():
    with open('./pipeline.lock', 'r', encoding='utf-8') as f:
        o = yaml.safe_load(f)

    harness_infos = {}
    split_harnesses_dir = o['repos']['target_harness_infos']['args']['basedir']
    for fname in os.listdir(split_harnesses_dir):
        with open(os.path.join(split_harnesses_dir, fname), 'r', encoding='utf-8') as f:
            harness_infos[fname.split('.yaml')[0]] = yaml.safe_load(f)

    benign_meta_dir = o['repos']['benign_harness_input_metadatas']['args']['basedir']

    benigns_per_harness = defaultdict(list)
    for f in os.listdir(benign_meta_dir):
        with open(os.path.join(benign_meta_dir, f), 'r', encoding='utf-8') as f:
            d = yaml.safe_load(f)
        benigns_per_harness[d['harness_info_id']].append(d)

    return harness_infos, benigns_per_harness

def check_mock_cp():
    ''' Check the results for mock-cp '''
    assert len(data['aflpp_fuzz_merge']['benigns_dir'][0]) >= 4, \
        f"Did not find at least 4 benigns in mock-cp?? {data['aflpp_fuzz_merge']}"
    assert len(data['aflpp_fuzz_merge']['crashes'][0]) >= 4, f"Did not find at least 4 crashes in mock-cp?? {data['aflpp_fuzz_merge']}"
    assert data['aflpp_fuzz']['harness_info'][0] == ['7322a79b2bb151ed30ad171478e527f5'], f"The format of the harnesses has changed?? make sure this does not break anything. {data['aflpp_fuzz']}"

def check_nginx_cp_semis():
    ''' Check if the nginx-cp-semis challenge ran correctly '''

    # assert len(data['aflpp_fuzz_merge']['benigns_dir'][0]) > 20, \
    #     f"Did not find at least 20 benigns in nginx?? {data['aflpp_fuzz_merge']}"
    # assert len(data['aflpp_fuzz_merge']['crashes'][0]) > 20, \
    #     f"Did not find at least 20 crashes in nginx?? {data['aflpp_fuzz_merge']}"
    assert sorted(data['aflpp_fuzz']['harness_info'][0]) == [
        '42beab12181fc202894584732cf2f517', 'b5a4ee2e12a44abf651359d22ea66ed9', 'd035a8f15da34000b29a1476b7b77dfd'
        ], f"The format of the harnesses has changed?? make sure this does not break anything. {data['aflpp_fuzz']}"

    harness_infos, benigns_per_harness = get_benigns_per_harness()
    satisfactory_amounts_found = True
    for harness_id, harness_info in harness_infos.items():
        benigns = benigns_per_harness[harness_id]
        print(f"Harness {harness_id}: {harness_info} has {len(benigns)} benign inputs ...")
        if len(benigns) < 10:
            satisfactory_amounts_found = False
            # print(f"Harness {harness_id} does not have at least 10 harness inputs??? Something is forked. {harness_infos=} {benigns=}")

    assert satisfactory_amounts_found, f"Some harnesses did not have enough benign inputs discovered??? Check that. {harness_infos=}, {benigns_per_harness=}"

def check_sqlite3_semis():
    pass

additional_checks = {
    'mock-cp': check_mock_cp,
    'challenge-004-nginx-cp-semis': check_nginx_cp_semis,
    'targets-semis-sqlite3': check_sqlite3_semis,
}.get(TARGET_NAME, lambda: None)()

print("Passed all checks!")