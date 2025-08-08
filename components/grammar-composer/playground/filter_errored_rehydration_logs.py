#!/usr/bin/env python3

import re
import sys

def process_report(filename):
    with open(filename, 'r') as file:
        content = file.read()
    
    # Define the regex pattern for block headers
    separator = r'={80,}\nHydrating grammar \(\d+/\d+\).*?\n={80,}'
    
    # Split the content into blocks
    block_pattern = re.compile(f'({separator}[\\s\\S]*?)(?={separator}|$)', re.DOTALL)
    blocks = block_pattern.findall(content)
    
    # Define error keywords
    error_keywords = ['error', 'fail', 'exception', 'except', 'panic', 'traceback', 'panic', 'panicked', 'stack trace']
    
    # Filter blocks with errors
    # Only keep the first block for any given error
    seen_errors = set()
    error_blocks = set()
    all_error_blocks = set()
    for block in blocks:
        # skip block header when matching error keywords
        _block = block.split("="*80)[2]
        for _line in _block.split("\n"):
            if any(keyword.lower() in _line.lower() for keyword in error_keywords):
                all_error_blocks.add(block)
                if _line not in seen_errors:
                    error_blocks.add(block)
                    seen_errors.add(_line)
    
    print(f"Found {len(error_blocks)} distinct errors in {len(all_error_blocks)} errored blocks.")
    
    return error_blocks

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <report_file>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    error_blocks = process_report(report_file)
    
    if error_blocks:
        print(f"Found {len(error_blocks)} blocks with errors:")
        for i, block in enumerate(error_blocks):
            print(f"\n--- Error Block {i+1} ---")
            print(block)
    else:
        print("No blocks with errors found.")

if __name__ == "__main__":
    main()