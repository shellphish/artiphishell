import hashlib
from enum import IntEnum

from patchery.utils import fuzzy_hash


class ProgramInputType(IntEnum):
    STDIN = 0
    ARGV = 1
    FILE = 2
    NETWORK = 3
    URL = 4


class ProgramInput:
    def __init__(self, data, input_type: ProgramInputType):
        self.data = data
        self.input_type = input_type

        _data = data.encode() if isinstance(data, str) else data
        hasher = hashlib.sha256()
        hasher.update(_data)
        self._hash = hasher.hexdigest()

    def __str__(self):
        return f"<ProgInput: {self._hash}>"

    def __repr__(self):
        return self.__str__()
