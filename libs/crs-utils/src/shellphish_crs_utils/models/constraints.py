from typing import Union
from pydantic import StringConstraints

PDT_ID = Union[str, int]

ID_REGEX = r"^id_[0-9]+$"
ID_CONSTRAINTS = StringConstraints(strip_whitespace=True, pattern=ID_REGEX)

SHA1_REGEX = r"[0-9a-f]{40}"
SHA1_CONSTRAINTS = StringConstraints(
    strip_whitespace=True,
    pattern=SHA1_REGEX,
    max_length=40,
    min_length=40,
)

MD5_REGEX = r"[0-9a-f]{32}"
MD5_CONSTRAINTS = StringConstraints(
    strip_whitespace=True,
    pattern=MD5_REGEX,
    max_length=32,
    min_length=32,
)