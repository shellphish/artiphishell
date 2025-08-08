#!/usr/bin/env python3
import argparse
import sys

def to_escaped_string(b: bytes) -> str:
    """Convert a bytes object to a quoted string with hex escaping
    applied to all non-printable, high-bit, or problematic characters."""
    result = '"'
    for byte in b:
        # Check if byte is printable (0x20-0x7E) and not a backslash or quote.
        if 0x20 <= byte < 0x7f and byte not in (ord('"'), ord('\\')):
            result += chr(byte)
        else:
            result += '\\x{:02x}'.format(byte)
    result += '"'
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize and merge dictionaries from multiple files.")
    parser.add_argument("files", nargs="+", help="Files to normalize")
    args = parser.parse_args()

    deduplicated = set()

    for filename in args.files:
        with open(filename, "rb") as f:
            for line in f:
                if line.startswith(b"# "):
                    continue
                # Remove trailing newline characters (both LF and CRLF)
                line = line.rstrip(b'\r\n')
                if line:  # skip empty lines
                    deduplicated.add(line)

    # Output each unique entry as an aflpp dictionary value.
    # Sorting the entries helps provide consistent output.
    for entry in sorted(deduplicated):
        sys.stdout.write(to_escaped_string(entry) + "\n")