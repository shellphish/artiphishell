from enum import IntEnum


class CodeParserBackend(IntEnum):
    CLANG = 0
    TREE_SITTER = 1
    PYJOERN = 2
