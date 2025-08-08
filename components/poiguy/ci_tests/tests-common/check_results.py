import json
import sys

print("Loading pd status results ... ")
data = json.load(sys.stdin)
print(json.dumps(data, indent=2))
print("Checking results ... ")

assert len(data['poiguy_kasan']['success'][0]) > 0, f"no reports were successfully parsed {data['poiguy_kasan']}"
assert len(data['poiguy_kasan']['pov_guy_report'][0]) == len(data['poiguy_kasan']['success'][0]), f"some reports failed to be parsed {data['poiguy_kasan']}"

print("Passed all checks!")
