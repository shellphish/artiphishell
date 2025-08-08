#!/usr/bin/env python3
from unidiff import PatchSet
import hashlib
import os
import logging

from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel("corpus-guy-diff-splitter", "input_generation", "corpus_selection")
TRACER = get_otel_tracer()

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("corpusguy")

CORPUSGUY_SYNC_TO_FUZZER = os.environ.get("CORPUSGUY_SYNC_TO_FUZZER")
DIFF_FILE = os.environ.get("DIFF_FILE")
OUTPUT_CORPUS_PATH = os.environ.get("OUTPUT_CORPUS_PATH")

log.info(f"CORPUSGUY_SYNC_TO_FUZZER: {CORPUSGUY_SYNC_TO_FUZZER}")
log.info(f"DIFF_FILE: {DIFF_FILE}")
log.info(f"OUTPUT_CORPUS_PATH: {OUTPUT_CORPUS_PATH}")

@TRACER.start_as_current_span("corpus-guy-diff-splitter.main")
def main():
    with open(DIFF_FILE) as f:
        patch = PatchSet(f)

    file_counter = 0
    for patched_file in patch:
        # A truly new file has:
        # 1. No removed lines (removed == 0)
        # 2. Source file is /dev/null or None
        # 3. is_added_file == True (though this can be unreliable)
        
        # Check source file first
        if patched_file.source_file not in [None, '/dev/null']:
            continue
            
        # Verify no removed lines exist
        if patched_file.removed > 0:
            continue
            
        log.info(f"Checking {patched_file.path}: source={patched_file.source_file}, "
                 f"added={patched_file.added}, removed={patched_file.removed}")
        
        # Extract content from all hunks
        content_lines = []
        for hunk in patched_file:
            for line in hunk:
                # Only include added lines (skip context lines)
                if line.is_added and line.value:
                    # line.value already excludes the '+' prefix
                    content_lines.append(line.value)
        
        if not content_lines:
            log.warning(f"No content found for {patched_file.path}")
            continue
            
        # Join lines to create file content
        content = ''.join(content_lines)
        
        # Generate hash and filename
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        filename = f"id:{str(file_counter).zfill(6)}_diff_new_file_{content_hash}"
        
        # Create output directory if it doesn't exist
        os.makedirs(OUTPUT_CORPUS_PATH, exist_ok=True)
        
        # Write the file
        output_path = os.path.join(OUTPUT_CORPUS_PATH, filename)
        log.info(f"Writing new file: {patched_file.path} -> {output_path}")
        with open(output_path, 'w') as out:
            out.write(content)
            
        file_counter += 1
    
    log.info(f"Extracted {file_counter} new files")

if __name__ == "__main__":
    main()