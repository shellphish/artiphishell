import json
import os
import sys

result = {}

OUT_PATH=sys.argv[1]

for val in sys.argv[2:]:
    with open(val, 'r') as f:
        data = json.load(f)
        assert val.endswith('.json')
        key = os.path.basename(val)[:-5]
        data = {"#select": data["#select"]}
        result[key] = data

with open(OUT_PATH, 'w') as f:
    json.dump(result, f)