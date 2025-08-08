from pathlib import Path

WORKDIR = Path(Path("/out/workdir.txt").read_text().strip())
WORKDIR_CLEAN = Path("/out/original_workdir")

VALID_SOURCE_FILE_SUFFIXES_C = [
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".c++",
    ".h",
    ".hpp",
    ".hh",
    ".hxx",
    ".h++",
    ".inl",
]
