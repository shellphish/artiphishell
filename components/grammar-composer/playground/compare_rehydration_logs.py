#!/usr/bin/env python3

import re
import sys
from collections import defaultdict

def collect_matches_and_errors(filename):
    with open(filename, 'r') as file:
        content = file.read()
    
    # Define the regex pattern for block headers
    separator = r'={80,}\nHydrating grammar \(\d+/\d+\).*?\n={80,}'
    
    # Split the content into blocks
    block_pattern = re.compile(f'({separator}[\\s\\S]*?)(?={separator}|$)', re.DOTALL)
    blocks = block_pattern.findall(content)
    
    # Create dictionaries to store matches and errors by filepath
    matches = defaultdict(set)
    errors = defaultdict(set)
    processed_files = set()
    
    # Define error keywords
    error_keywords = ['error', 'fail', 'exception', 'except', 'panic', 'panicked', 'stack trace', 'traceback']
    
    for block in blocks:
        # Extract the grammar filepath from the header
        header_match = re.search(r'Hydrating grammar \(\d+/\d+\) from (.*?)\n', block)
        if header_match:
            filepath = header_match.group(1)
            processed_files.add(filepath)
            
            # Check for errors
            has_error = False
            error_lines = []
            
            for line in block.split('\n'):
                if any(keyword.lower() in line.lower() for keyword in error_keywords):
                    has_error = True
                    error_lines.append(line.strip())
            
            if has_error:
                errors[filepath] = set(error_lines)
            
            # Collect matches (even if there are errors)
            confidence_matches = re.findall(r'\[MAGIC\] Rule .*? matches (.*?) with confidence (.*?)$', 
                                          block, re.MULTILINE)
            
            for match_type, confidence in confidence_matches:
                if confidence.strip() == "1.0":
                    # Store just "matches ZIP with confidence 1.0" type format
                    matches[filepath].add(f"matches {match_type} with confidence 1.0")
    
    return matches, errors, processed_files

def compare_logs(log1, log2):
    matches1, errors1, files1 = collect_matches_and_errors(log1)
    matches2, errors2, files2 = collect_matches_and_errors(log2)
    
    # Find filepaths that exist in both logs
    common_filepaths = files1.intersection(files2)
    
    # Compare matches for each common filepath
    differences = {}
    
    for filepath in common_filepaths:
        matches_in_1 = matches1.get(filepath, set())
        matches_in_2 = matches2.get(filepath, set())
        
        # Only consider matches in log1 but not in log2
        only_in_1 = matches_in_1 - matches_in_2
        
        # Only add to differences if there are matches in log1 but not in log2
        if only_in_1:
            differences[filepath] = {
                'only_in_log1': only_in_1,
                'error_in_log2': filepath in errors2
            }
            if filepath in errors2:
                differences[filepath]['error_lines_log2'] = errors2[filepath]
    
    return differences

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <rehydration-log-first-hit.txt> <rehydration-log-second.txt>")
        sys.exit(1)
    
    log1_file = sys.argv[1]
    log2_file = sys.argv[2]
    
    print(f"Comparing matches between {log1_file} and {log2_file}...")
    
    differences = compare_logs(log1_file, log2_file)
    
    if not differences:
        print("\nNo matches found only in first log file for grammar files present in both logs.")
        return
    
    print(f"\nFound {len(differences)} files with matches only in {log1_file}:")
    
    for filepath, diff in differences.items():
        print(f"\n--- File: {filepath} ---")
        print(f"  To reproduce: ./playground/test_grammars.py '{filepath}'")
        
        # Print whether the second log has an error for this file
        error_status = "ERROR" if diff.get('error_in_log2', False) else "NO ERROR"
        print(f"  Second log status: {error_status}")
        
        # If there's an error, show the first error line
        if diff.get('error_in_log2', False) and 'error_lines_log2' in diff:
            first_error = next(iter(diff['error_lines_log2']))
            print(f"  Error sample: {first_error}")
        
        # Print matches only in the first log
        print(f"  Matches only in {log1_file}:")
        for match in diff['only_in_log1']:
            print(f"    {match}")

if __name__ == "__main__":
    main()