#!/usr/bin/env python3

import hashlib
import json
import os
import logging
import time
import yaml

from collections import defaultdict, deque
from glob import glob

from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.coverage import FileCoverageMap, FunctionCoverageMap

from coveragelib import Tracer
from coveragelib.parsers.function_coverage import C_FunctionCoverageParser_Profraw, Java_FunctionCoverageParser_Jacoco

from morpheus.config import REFERENCE_GRAMMARS_FILEPATHS
from morpheus.composable import Composable, Composition
from morpheus.fingerprint import RuleFingerprint
from morpheus.magic import MIME_TO_NAME
from morpheus.derivation_tree import DerivationTree
from morpheus.grammar import Grammar
from morpheus.utils import exception_wrapper

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("ron-composer")

# Load environment variables
PROJECT_METADATA_PATH = os.environ.get("PROJECT_METADATA_PATH")
HARNESS_INFO_PATH = os.environ.get("HARNESS_INFO_PATH")
PROJECT_DIR = os.environ.get("PROJECT_DIR")
FUNCTIONS_INDEX_PATH = os.environ.get("FUNCTIONS_INDEX_PATH")
FUNCTIONS_JSONS_DIR_PATH = os.environ.get("FUNCTIONS_JSONS_DIR_PATH")
ARTIPHISHELL_RON_READ_SYNC_PATH = os.environ.get("ARTIPHISHELL_RON_READ_SYNC_PATH")
ARTIPHISHELL_RON_WRITE_SYNC_PATH = os.environ.get("ARTIPHISHELL_RON_WRITE_SYNC_PATH")

log.info(f"PROJECT_METADATA_PATH: {PROJECT_METADATA_PATH}")
log.info(f"HARNESS_INFO_PATH: {HARNESS_INFO_PATH}")
log.info(f"PROJECT_DIR: {PROJECT_DIR}")
log.info(f"FUNCTIONS_INDEX_PATH: {FUNCTIONS_INDEX_PATH}")
log.info(f"FUNCTIONS_JSONS_DIR_PATH: {FUNCTIONS_JSONS_DIR_PATH}")
log.info(f"ARTIPHISHELL_RON_READ_SYNC_PATH: {ARTIPHISHELL_RON_READ_SYNC_PATH}")
log.info(f"ARTIPHISHELL_RON_WRITE_SYNC_PATH: {ARTIPHISHELL_RON_WRITE_SYNC_PATH}")

CURRENT_ID = len(os.listdir(ARTIPHISHELL_RON_WRITE_SYNC_PATH)) + 1

rons_seen_filepaths = set()
rons_seen_hashes = set()
rons_pending = dict()

RULEHASH_PARENTHASH_TO_RON = defaultdict(set)
RULEHASH_PARENTHASH_TO_MIMES = defaultdict(lambda: deque(maxlen=5))  # keep only the last 5 mimes
RULEHASH_PARENTHASH_TO_FINGERPRINTS = defaultdict(RuleFingerprint)
RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS = defaultdict(set)

with open("/shellphish/grammar-composer/reference_fingerprints.json") as f:
    REFERENCE_FINGERPRINTS = json.load(f)

@exception_wrapper()
def main(tracer: Tracer):
    global rons_seen_hashes, rons_pending, CURRENT_ID, RULEHASH_PARENTHASH_TO_RON, RULEHASH_PARENTHASH_TO_MIMES, RULEHASH_PARENTHASH_TO_FINGERPRINTS, RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS
    
    # Read pending rons to be improved from ARTIPHISHELL_RON_READ_SYNC_PATH directory
    for filepath in glob(f"{ARTIPHISHELL_RON_READ_SYNC_PATH}/**/*", recursive=True):
        if not os.path.isfile(filepath):
            # Skip if not a file
            continue
        if filepath.endswith("_composed_ron"):
            # Skip rons that have already being processed
            # NOTE: this works well with jazzer, but afl renames when syncing
            continue
        if filepath in rons_seen_filepaths:
            #  Skip rons that have already been seen
            continue
        else:
            # Else check content hash (because rons are copied from ARTIPHISHELL_RON_WRITE_SYNC_PATH to ARTIPHISHELL_RON_READ_SYNC_PATH)
            with open(filepath, "rb") as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()
            if content_hash in rons_seen_hashes:
                # Skip rons that have already been seen (by content hash)
                continue
        rons_pending[content_hash] = filepath

    # Wait to make sure that all the pending rons are fully written
    time.sleep(1)

    if not rons_pending:
        log.info("Waiting for new rons...")
        return
        
    while rons_pending:
        content_hash, ron_path = rons_pending.popitem()
        current_dt = DerivationTree.from_file(ron_path)
        rons_seen_filepaths.add(ron_path)
        rons_seen_hashes.add(content_hash)
        log.info(f"Processing ron: {(ron_path, content_hash)}")

        if current_dt is None:
            log.error(f"Failed to load ron from {ron_path}. Skipping...")
            continue

        def write_if_new_coverage(old_covered_functions, new_dt):
            global CURRENT_ID, rons_seen_filepaths, rons_seen_hashes
            log.info("Assessing coverage for the new ron...")
            for f in new_dt.approximate_covered_functions(tracer):
                if f not in old_covered_functions:
                    log.info(f"At least one new function found: {f}. Adding ron.")
                    break
            else:
                log.info("No new functions found. Skipping ron.")
                return False
            # Write the improved ron to the ARTIPHISHELL_RON_WRITE_SYNC_PATH directory
            new_ron_serialized = new_dt.to_ron_bytes()
            new_filename = f"id:{str(CURRENT_ID).zfill(6)}_{new_dt.hexdigest}_composed_ron"
            new_content_hash = hashlib.sha256(new_ron_serialized).hexdigest()
            new_ron_path = os.path.join(ARTIPHISHELL_RON_WRITE_SYNC_PATH, new_filename)

            with open(new_ron_path, "wb") as f:
                f.write(new_ron_serialized)

            # Mark the ron as done
            rons_seen_filepaths.add(new_ron_path)
            rons_seen_hashes.add(new_content_hash)

            # Update the current ID
            CURRENT_ID += 1

            log.info(f"DerivationTree improved. New ron written to: {new_ron_path}")
            return True

        # DO THE OLD COMPOSITIONS APPLY TO THE CURRENT RON?
        log.info("Applying old compositions to the current ron...")
        current_covered_functions = None
        for rule_hash, parent_hash in {(node.rule.hexdigest, current_dt.get_parent(node).rule.hexdigest if current_dt.get_parent(node) else None) for node in current_dt.nodes}:
            # any active_compositions for rulehash-parenthash?
            for composition in RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS[(rule_hash, parent_hash)]:
                # has the composition been applied already?
                if composition.hexdigest in current_dt.applied_compositions:
                    continue
                log.info(f"Applying composition {composition.hexdigest} to ron @ {ron_path}")
                # apply the composition
                for new_dt in current_dt.iter_single_rule_compositions(composition):
                    if current_covered_functions is None:
                        current_covered_functions = set(current_dt.approximate_covered_functions(tracer))
                    write_if_new_coverage(current_covered_functions, new_dt)
        
        ################################################################
        # IS THERE ANY NEW COMPOSITION?
        ################################################################
        # first update the data structs
        all_rulehash_parenthash_pairs = set()
        for node in current_dt.tree.nodes:
            if not node.rule.is_composable():
                continue
            rule_hash = node.rule.hexdigest
            parent_node = current_dt.get_parent(node)
            parent_hash = parent_node.rule.hexdigest if parent_node else None
            all_rulehash_parenthash_pairs.add((rule_hash, parent_hash))
            # update the rulehash-parenthash to rons mapping
            RULEHASH_PARENTHASH_TO_RON[(rule_hash, parent_hash)].add(current_dt.filepath)
            # update the rulehash-parenthash to mimes mapping
            (mime, encoding) = Composable.magic_guess_one(node.value)
            RULEHASH_PARENTHASH_TO_MIMES[(rule_hash, parent_hash)].append((mime, encoding))
            # update the rulehash-parenthash to fingerprints mapping
            RULEHASH_PARENTHASH_TO_FINGERPRINTS[(rule_hash, parent_hash)].update(node.value[:4].ljust(4, b'\x00'))

        log.info("Finding new compositions...")
        new_compositions = set()
        for rule_hash, parent_hash in all_rulehash_parenthash_pairs:
            # new composition by mime?
            if len(RULEHASH_PARENTHASH_TO_MIMES[(rule_hash, parent_hash)]) >= 5 and RULEHASH_PARENTHASH_TO_MIMES[(rule_hash, parent_hash)][0] != (None, None) and len(set(RULEHASH_PARENTHASH_TO_MIMES[(rule_hash, parent_hash)])) == 1:
                # there is only one mime, new composition!
                mime, encoding = RULEHASH_PARENTHASH_TO_MIMES[(rule_hash, parent_hash)][0]
                mime_name = MIME_TO_NAME.get(mime, None)

                for reference_grammar_name, reference_grammar_filepath in REFERENCE_GRAMMARS_FILEPATHS.items():
                    if reference_grammar_name == mime_name or reference_grammar_name.startswith(f"{mime_name}@"):
                        external_grammar = Grammar._from_file(reference_grammar_name, reference_grammar_filepath)
                        composition = Composition(rule_hash, parent_hash, external_grammar, external_rule=None, external_nonterm="START", encoding=encoding)
                        if composition not in RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS[(rule_hash, parent_hash)]:
                            log.info(f"Found new composition by mime: {composition}")
                            RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS[(rule_hash, parent_hash)].add(composition)
                            new_compositions.add(composition)

            # new composition by fingerprint?
            fp = RULEHASH_PARENTHASH_TO_FINGERPRINTS[(rule_hash, parent_hash)]
            if fp.num_observations >= 5 and fp.to_hex() in REFERENCE_FINGERPRINTS:
                # there is a reference fingerprint, new composition!
                for reference_grammar_name, reference_nonterm, encoding in REFERENCE_FINGERPRINTS[fp.to_hex()]:

                    if reference_grammar_name in REFERENCE_GRAMMARS_FILEPATHS:
                        external_grammar = Grammar._from_file(reference_grammar_name, REFERENCE_GRAMMARS_FILEPATHS[reference_grammar_name])
                        composition = Composition(rule_hash, parent_hash, external_grammar, external_rule=None, external_nonterm=reference_nonterm, encoding=encoding)
                        if composition not in RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS[(rule_hash, parent_hash)]:
                            log.info(f"Found new composition by fingerprint: {composition}")
                            RULEHASH_PARENTHASH_TO_ACTIVE_COMPOSITIONS[(rule_hash, parent_hash)].add(composition)
                            new_compositions.add(composition)

        log.info(f"Found {len(new_compositions)} new compositions.")

        # DO THE NEW COMPOSITIONS APPLY TO ANY OLD RON?
        relevant_ron_filepaths = set()
        for composition in new_compositions:
            rule_hash = composition.internal_rule_hash
            parent_hash = composition.internal_parent_hash
            # find all ron_filepaths with (internal_rule_hash, internal_parent_hash)
            ron_filepaths = RULEHASH_PARENTHASH_TO_RON[(rule_hash, parent_hash)]
            relevant_ron_filepaths.update(ron_filepaths)
        
        log.info(f"Found {len(relevant_ron_filepaths)} relevant (old) rons for the new compositions.")
        for ron_filepath in relevant_ron_filepaths:
            old_dt = DerivationTree.from_file(ron_filepath)
            old_covered_functions = None

            for composition in new_compositions:
                rule_hash = composition.internal_rule_hash
                parent_hash = composition.internal_parent_hash
                # find all ron_hashes with (internal_rule_hash, internal_parent_hash)
                if ron_filepath in RULEHASH_PARENTHASH_TO_RON[(rule_hash, parent_hash)]:
                    # NOTE: no need to check if the (NEW) composition has been applied already
                    # apply the composition to the ron
                    log.info(f"Applying composition {composition.hexdigest} to ron @ {ron_filepath}")
                    # apply the composition
                    for new_dt in old_dt.iter_single_rule_compositions(composition):
                        if old_covered_functions is None:
                            old_covered_functions = set(old_dt.approximate_covered_functions(tracer))
                        write_if_new_coverage(old_covered_functions, new_dt)


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
