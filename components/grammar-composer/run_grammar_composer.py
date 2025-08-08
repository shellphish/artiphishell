#!/usr/bin/env python3

import hashlib
import itertools
import os
import logging
import time
import yaml

from collections import defaultdict
from pathlib import Path

from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.coverage import FileCoverageMap, FunctionCoverageMap

from coveragelib import Tracer
from coveragelib.parsers.function_coverage import C_FunctionCoverageParser_Profraw, Java_FunctionCoverageParser_Jacoco

from morpheus.grammar import Grammar
from morpheus.utils import exception_wrapper

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("grammar-composer")

# Load environment variables
PROJECT_METADATA_PATH = os.environ.get("PROJECT_METADATA_PATH")
HARNESS_INFO_PATH = os.environ.get("HARNESS_INFO_PATH")
PROJECT_DIR = os.environ.get("PROJECT_DIR")
FUNCTIONS_INDEX_PATH = os.environ.get("FUNCTIONS_INDEX_PATH")
FUNCTIONS_JSONS_DIR_PATH = os.environ.get("FUNCTIONS_JSONS_DIR_PATH")
TARGET_SPLIT_METADATA_PATH = os.environ.get("TARGET_SPLIT_METADATA_PATH")
ARTIPHISHELL_FUZZER_SYNC_BASE_DIR = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_BASE_DIR")
ARTIPHISHELL_PROJECT_NAME = os.environ.get("ARTIPHISHELL_PROJECT_NAME")
ARTIPHISHELL_HARNESS_NAME = os.environ.get("ARTIPHISHELL_HARNESS_NAME")
ARTIPHISHELL_HARNESS_INFO_ID = os.environ.get("ARTIPHISHELL_HARNESS_INFO_ID")
ARTIPHISHELL_GRAMMARS_SYNC_PATH = os.environ.get("ARTIPHISHELL_GRAMMARS_SYNC_PATH")

log.info(f"PROJECT_METADATA_PATH: {PROJECT_METADATA_PATH}")
log.info(f"HARNESS_INFO_PATH: {HARNESS_INFO_PATH}")
log.info(f"PROJECT_DIR: {PROJECT_DIR}")
log.info(f"FUNCTIONS_INDEX_PATH: {FUNCTIONS_INDEX_PATH}")
log.info(f"FUNCTIONS_JSONS_DIR_PATH: {FUNCTIONS_JSONS_DIR_PATH}")
log.info(f"TARGET_SPLIT_METADATA_PATH: {TARGET_SPLIT_METADATA_PATH}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_BASE_DIR: {ARTIPHISHELL_FUZZER_SYNC_BASE_DIR}")
log.info(f"ARTIPHISHELL_PROJECT_NAME: {ARTIPHISHELL_PROJECT_NAME}")
log.info(f"ARTIPHISHELL_HARNESS_NAME: {ARTIPHISHELL_HARNESS_NAME}")
log.info(f"ARTIPHISHELL_HARNESS_INFO_ID: {ARTIPHISHELL_HARNESS_INFO_ID}")
log.info(f"ARTIPHISHELL_GRAMMARS_SYNC_PATH: {ARTIPHISHELL_GRAMMARS_SYNC_PATH}")

ARTIPHISHELL_GRAMMARS_SYNC_ALL_PATHS = []
# Load the metadata file (yaml)
metadata_path = Path(TARGET_SPLIT_METADATA_PATH)
with open(metadata_path, 'r') as file:
    metadata = yaml.safe_load(file)
# Look through metadata["harness_infos"]
for harness_info_id, data in sorted(metadata["harness_infos"].items()):
    if data["cp_harness_name"] == ARTIPHISHELL_HARNESS_NAME:
        sync_path = os.path.join(ARTIPHISHELL_FUZZER_SYNC_BASE_DIR, 
                                 f"{ARTIPHISHELL_PROJECT_NAME}-{ARTIPHISHELL_HARNESS_NAME}-{harness_info_id}", 
                                 "sync-grammars", "nautilus-python")
        if not os.path.exists(sync_path):
            os.makedirs(sync_path, exist_ok=True)
        ARTIPHISHELL_GRAMMARS_SYNC_ALL_PATHS.append(sync_path)

grammars_seen_filenames = set()
grammars_seen_hashes = set()
grammars_pending = dict()

@exception_wrapper()
def main(tracer: Tracer):
    global grammars_seen_filenames, grammars_seen_hashes, grammars_pending

    # Read pending grammars to be improved from ARTIPHISHELL_GRAMMARS_SYNC_PATH directory
    for filename in os.listdir(ARTIPHISHELL_GRAMMARS_SYNC_PATH):
        if not os.path.isfile(os.path.join(ARTIPHISHELL_GRAMMARS_SYNC_PATH, filename)) or filename.startswith("token_grammar_"):
            # Skip non-regular-files and token grammars
            continue
        if not filename.endswith(".py"):
            continue
        if filename.startswith("composer_grammar_"):
            # Skip grammars that are already being seen
            continue
        if filename not in grammars_seen_filenames:
            with open(os.path.join(ARTIPHISHELL_GRAMMARS_SYNC_PATH, filename), "r") as f:
                content_hash = hashlib.md5(f.read().encode()).hexdigest()
            if content_hash in grammars_seen_hashes:
                # Skip grammars that have already been seen (by content hash)
                continue
            grammars_pending[content_hash] = filename

    # Wait to make sure that all the pending grammars are fully written
    time.sleep(1)

    if not grammars_pending:
        log.info("Waiting for new grammars...")
        return
        

    while grammars_pending:
        content_hash, filename = grammars_pending.popitem()
        grammar_path = os.path.join(ARTIPHISHELL_GRAMMARS_SYNC_PATH, filename)
        grammars_seen_filenames.add(filename)
        grammars_seen_hashes.add(content_hash)
        log.info(f"Processing grammar: {filename}")

        old_grammar = Grammar.from_file(grammar_path)
        old_covered_functions = None

        if old_grammar is None:
            log.error(f"Failed to load grammar from {grammar_path}. Skipping...")
            continue

        # Try to improve the grammar
        log.info("Hydrating the grammar...")
        for new_grammar in itertools.islice(old_grammar.iter_compositions(), 10):
            # Check if the new grammar "improves" the old grammar

            if old_covered_functions is None:
                log.info("Assessing coverage for the old grammar...")
                old_covered_functions = set(old_grammar.approximate_covered_functions(tracer, batch_size=5))

            log.info("Assessing coverage for the new grammar...")
            for f in new_grammar.approximate_covered_functions(tracer, batch_size=5):
                if f not in old_covered_functions:
                    log.info(f"New function found: {f}. Adding grammar.")
                    break
            else:
                log.info("No new functions found. Skipping grammar.")
                continue

            # Write the improved grammar to the ARTIPHISHELL_GRAMMARS_SYNC_PATH directory
            new_grammar_serialized = new_grammar.serialize()
            new_filename = f"composer_grammar_{hashlib.md5(new_grammar_serialized.encode()).hexdigest()}.py"
            new_content_hash = hashlib.md5(new_grammar_serialized.encode()).hexdigest()

            for sync_path in ARTIPHISHELL_GRAMMARS_SYNC_ALL_PATHS:
                new_grammar_path = os.path.join(sync_path, new_filename)
                with open(new_grammar_path, "w") as f:
                    f.write(new_grammar_serialized)

            # Mark the grammar as done
            grammars_seen_filenames.add(new_filename)
            grammars_seen_hashes.add(new_content_hash)
            
            log.info(f"Grammar improved. New grammar written to: {new_grammar_path}")

if __name__ == "__main__":
    # load project metadata and harness info
    with open(HARNESS_INFO_PATH, "r") as f:
        harness_info = HarnessInfo.model_validate(yaml.safe_load(f))
    with open(PROJECT_METADATA_PATH, "r") as f:
        project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

    harness_name = harness_info.cp_harness_name
    
    parser = {
        LanguageEnum.c: C_FunctionCoverageParser_Profraw,
        LanguageEnum.cpp: C_FunctionCoverageParser_Profraw,
        LanguageEnum.jvm: Java_FunctionCoverageParser_Jacoco,
    }[project_metadata.language]()

    # Dynamic timeout per language
    if project_metadata.language == LanguageEnum.jvm:
        timeout_per_seed = 15
    else:
        timeout_per_seed = 1

    # Start the tracer in aggregate mode
    with Tracer(PROJECT_DIR, harness_info.cp_harness_name, parser=parser, aggregate=True, timeout_per_seed=timeout_per_seed, debug_mode=False) as tracer:
        while True:
            try:
                main(tracer)
            except:
                log.exception(f"Error in main loop. Restarting...")
                time.sleep(1)
