import os
import yaml
from pathlib import Path
import time

INPUT_DIR = Path(os.environ.get("BUILD_CONFIG_INPUT_DIR", ""))
OUTPUT_DIR = Path(os.environ.get("BUILD_CONFIG_OUTPUT_FILE", ""))
META_FILE = os.environ.get("HARNESS_METADATA", "")

with open(META_FILE, "r") as f:
    harness_metadata_info = yaml.safe_load(f)
    expected = harness_metadata_info["num_build_configs"]

assert INPUT_DIR.is_dir(), f"{INPUT_DIR} is not a directory"
wait = 0
while len(os.listdir(INPUT_DIR)) != expected:
    print(f"Waiting for harnesses to be generated in {INPUT_DIR}...")
    time.sleep(5)
    wait += 1
    if wait > 60:  # Timeout after 5 minutes
        raise TimeoutError(f"Timeout waiting for build configurations in {INPUT_DIR}")

aggr = {}
for build_config_file in INPUT_DIR.iterdir():
    build_config_id = Path(build_config_file).stem
    data = yaml.safe_load(build_config_file.read_text())
    aggr[build_config_id]= data

with open(OUTPUT_DIR, "w") as f:
    yaml.safe_dump(aggr, f)

print(f"Aggregated build configurations written to {OUTPUT_DIR}")
