from pathlib import Path

from .defs import VALID_SOURCE_FILE_SUFFIXES_C


def safe_decode(bs: bytes):
    assert isinstance(bs, bytes), "Expected bytes input"
    try:
        return bs.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return bs.decode("latin-1")
        except UnicodeDecodeError:
            return bs.decode("utf-8", errors="replace")


def resolve_output_file(compile_args):
    for entry in compile_args:
        if "output" in entry:
            continue

        file_path = Path(entry["file"])
        arguments = entry["arguments"]

        if "-c" in arguments and file_path.suffix in VALID_SOURCE_FILE_SUFFIXES_C:
            entry["output"] = file_path.with_suffix(".o").name
        elif "-S" in arguments and file_path.suffix in VALID_SOURCE_FILE_SUFFIXES_C:
            entry["output"] = file_path.with_suffix(".s").name
        elif "-E" in arguments or "-fsyntax-only" in arguments:
            continue  # No file output
        else:
            entry["output"] = "a.out"  # Default executable
