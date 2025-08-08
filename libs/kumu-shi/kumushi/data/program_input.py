import hashlib
from enum import IntEnum


class ProgramInputType(IntEnum):
    STDIN = 0
    ARGV = 1
    FILE = 2
    NETWORK = 3
    URL = 4


class ProgramInput:
    HUMAN_REDABILITY_THRESHOLD = 0.5

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

    def __hash__(self):
        return hash(str(self._hash) + str(self.input_type))

    def __eq__(self, other):
        if not isinstance(other, ProgramInput):
            return False
        return self._hash == other._hash and self.input_type == other.input_type

    def is_human_readable(self) -> bool:
        if not self.data:
            return False

        data = self.data.encode() if isinstance(self.data, str) else self.data
        score = self.human_readability_score(data)
        return score >= self.HUMAN_REDABILITY_THRESHOLD

    @staticmethod
    def human_readability_score(data: bytes) -> float:
        """
        Estimate how human-readable a blob of bytes is.
        Returns a float between 0 (not readable) and 1 (fully readable).
        Penalizes control and replacement characters.
        """
        if not data:
            return 0.0

        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return 0.0

        total = len(text)
        if total == 0:
            return 0.0

        good = 0
        for c in text:
            if c == '�':  # Unicode replacement
                continue
            if c.isprintable() or c.isspace():
                good += 1

        return good / total

