#!/usr/bin/env python3

from ruamel.yaml import YAML
import json

FILE = "run-arvo-pipeline.yaml"
TARGETS_FILE = "arvo-targets.json"

with open(TARGETS_FILE, 'r') as file:
    targets = json.load(file)

targets_list = []
for target in targets['targets']:
    targets_list.append(target['name'])

with open(FILE, 'r') as file:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    data = yaml.load(file)

to_update = data['on']['workflow_dispatch']['inputs']['target-name']['options']
for target in targets_list:
    if target not in to_update:
        to_update.append(target)

data['on']['workflow_dispatch']['inputs']['num-targets']['default'] = len(to_update) - 1
with open(FILE, 'w') as file:
    yaml.dump(data, file)
print(f"Updated {FILE} with new targets.")