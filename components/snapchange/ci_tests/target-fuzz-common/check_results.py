import json
import sys

TARGET_NAME = sys.argv[1]
DURATION = sys.argv[2]
print("Loading pd status results ... ")
data = json.load(sys.stdin)
print(json.dumps(data, indent=2))
print("Checking results ... ")


assert data['snapchange_take_snapshot']['success'][0] == ["1"], f"snapchange snapshot failed? {data['snapchange_take_snapshot']}"
assert data['snapchange_take_snapshot']['snapshot_snapchange_dir'][0] == ["1"], f"snapchange snapshot failed? {data['snapchange_take_snapshot']}"

assert data['snapchange_fuzz']['syzlang_grammar_input'][0] == ['1'], f"no grammar provided? {data['snapchange_fuzz']}"
assert len(data['snapchange_fuzz']['crashing_harness_inputs'][0]) >= 1, f"no crash found? {data['snapchange_fuzz']}"
assert len(data['snapchange_fuzz']['crash_coverage_dir'][0]) >= 1, f"no crash coverage? {data['snapchange_fuzz']}"
#assert len(data['snapchange_fuzz']['benign_harness_inputs'][0]) >= 1, f"no benigns found? {data['snapchange_fuzz']}"
#assert len(data['snapchange_fuzz']['benign_coverage_dir'][0]) >= 1, f"no benign coverage? {data['snapchange_fuzz']}"

print("Passed all checks!")
