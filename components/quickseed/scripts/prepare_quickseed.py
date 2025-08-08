import argparse
from pathlib import Path
import yaml
import os
import time

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Aggreate the harness infos together")
    argparser.add_argument(
        "--harnesses-dir",
        type=Path,
        help="The directory containing the harnesses"
    )
    argparser.add_argument(
        "--aggregated-harness",
        type=Path,
        help="The aggregated harness file"
    )
    argparser.add_argument(
        "--harness-metadata",
        type=Path,
        help="The harness metadata file"
    )
    args = argparser.parse_args()
    harnesses_dir = args.harnesses_dir
    aggregated_harness = args.aggregated_harness
    harness_metadata = args.harness_metadata

    project_id = None
    build_config = None
    project_name = None
    architecture = None
    sanitizer = None
    aggregated_harness_info = {
        "harnesses": []
    }
    with open(harness_metadata, "r") as f:
        harness_metadata_info = yaml.safe_load(f)
        harness_num = harness_metadata_info["num_harnesses"]
        harness_info_keys = harness_metadata_info["harness_info_keys"]
    found_all = False
    while True:
        assert harnesses_dir.is_dir(), f"{harnesses_dir} is not a directory"
            # Iterate through all files in the directory
        filenames = []
        for filename in os.listdir(harnesses_dir):
            # Get the name without extension using os.path.splitext()
            name_without_extension = os.path.splitext(filename)[0]
            filenames.append(name_without_extension)
        if set(harness_info_keys).issubset(set(filenames)):
            break
        print(f"Waiting for harnesses to be generated in {harnesses_dir}...")
        time.sleep(5)

    for harness_info in harnesses_dir.iterdir():
        harness_info_id = Path(harness_info).stem
        if str(harness_info_id) not in harness_info_keys:
            print(f"Skipping {harness_info_id} as it is not in the harness info keys")
            continue
    # for harness_info_id in harness_info_keys:
    #     harness_info = harnesses_dir / f"{harness_info_id}.yaml"
        data = yaml.safe_load(harness_info.read_text())
        if project_id is None:
            project_id = data["project_id"]
        if build_config is None:
            build_config = data["build_configuration_id"]
        if project_name is None:
            project_name = data["project_name"]
        if architecture is None:
            architecture = data["architecture"]
        if sanitizer is None:
            sanitizer = data["sanitizer"]
        data["harness_info_id"] = harness_info_id
        aggregated_harness_info["harnesses"].append(data)
    aggregated_harness_info["project_id"] = project_id
    aggregated_harness_info["build_configuration_id"] = build_config
    aggregated_harness_info["project_name"] = project_name
    aggregated_harness_info["architecture"] = architecture
    aggregated_harness_info["sanitizer"] = sanitizer
    with open(aggregated_harness, "w") as f:
        yaml.safe_dump(aggregated_harness_info, f)
    print(f"Aggregated harness info saved to {aggregated_harness}")
