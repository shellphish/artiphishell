#!/usr/bin/env python3
import argparse
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize and merge dictionaries from multiple files.")
    parser.add_argument("files", nargs="+", help="Files to normalize")
    args = parser.parse_args()

    deduplicated = set()

    for filename in args.files:
        with open(filename, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                elif line.startswith(b"#"):
                    continue
                
                # quote if unquoted
                if b'"' not in line:
                    line = b'"' + line + b'"'

                # find first = before quotes
                first_quote = line.find(b'"') if b'"' in line else None
                first_equal_sign = line.find(b"=") if b"=" in line else None
                if (first_equal_sign is not None) and (first_quote is not None) and (first_equal_sign < first_quote):
                    after_equal = line[first_equal_sign+1:]
                    deduplicated.add(after_equal)
                # else add whole line
                else:
                    deduplicated.add(line)

    # discard long tokens
    deduplicated = {d for d in deduplicated if len(d[1:-1].decode("unicode_escape").encode("latin1")) <= 32}

    for line in sorted(deduplicated):
        if 0 < len(line[1:-1].decode("unicode_escape").encode("latin1")) <= 32:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.write(b"\n")
                
# NOTE: rst has entries with double closing quotes
# NOTE: regexp has entries with unescaped quotes 
# NOTE: atom has entries with unclosed quotes
