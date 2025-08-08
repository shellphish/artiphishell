import logging
import os
import yaml

from pathlib import Path

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("coverage-guy")

# Load environment variables
ARTIPHISHELL_HARNESS_NAME = os.environ.get("ARTIPHISHELL_HARNESS_NAME")
ARTIPHISHELL_HARNESS_INFO_ID = os.environ.get("ARTIPHISHELL_HARNESS_INFO_ID")
TARGET_SPLIT_METADATA_PATH = os.environ.get("TARGET_SPLIT_METADATA_PATH")

log.info(f"ARTIPHISHELL_HARNESS_NAME: {ARTIPHISHELL_HARNESS_NAME}")
log.info(f"ARTIPHISHELL_HARNESS_INFO_ID: {ARTIPHISHELL_HARNESS_INFO_ID}")
log.info(f"TARGET_SPLIT_METADATA_PATH: {TARGET_SPLIT_METADATA_PATH}")

if __name__ == "__main__":
    # Load the metadata file (yaml)
    metadata_path = Path(TARGET_SPLIT_METADATA_PATH)
    with open(metadata_path, 'r') as file:
        metadata = yaml.safe_load(file)

    # Look through metadata["harness_infos"]
    for harness_info_id, data in sorted(metadata["harness_infos"].items()):
        if data["cp_harness_name"] == ARTIPHISHELL_HARNESS_NAME:
            log.error(f"The chosen harness info ID is: {harness_info_id}")
            log.error(f"Our harness info ID is: {ARTIPHISHELL_HARNESS_INFO_ID}")
            if harness_info_id != ARTIPHISHELL_HARNESS_INFO_ID:
                log.error("The harness info ID is not the first in the sorted list of harness info IDs. Exiting.")
                exit(1)
            else:  # harness_info_id == ARTIPHISHELL_HARNESS_INFO_ID:
                log.info("The harness info ID is the first in the sorted list of harness info IDs. Continuing.")
                exit(0)