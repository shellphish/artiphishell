import logging
from pathlib import Path
from typing import Optional, Dict, List
import hashlib

from .program_poi import ProgramPOI
from ..utils import fuzzy_hash, md5_hash

from unidiff import PatchSet, PatchedFile

_l = logging.getLogger(__name__)


class Patch:
    def __init__(
        self,
        poi: ProgramPOI,
        new_code: Optional[str] = None,
        old_code: Optional[str] = None,
        reasoning: Optional[str] = None,
        # useful for ranking purposes
        diff: Optional[str] = None,
        file_path: Optional[Path] = None,
        patched_file_data: Optional[PatchedFile] = None,
    ):
        self.poi = poi
        self.new_code = new_code or ""
        self.old_code = old_code or ""
        self.reasoning = reasoning

        if new_code:
            hash_data = new_code.encode()
        elif diff:
            hash_data = diff.encode()
        else:
            hash_data = b""
            _l.warning("No data to hash for patch, this is likely a bad Patch object")

        # TODO: I'd like to put back fuzzy hashing at some point!
        self.patch_hash = md5_hash(hash_data)

        # for caching purposes
        self.diff = diff or None
        self.patched_file_data = patched_file_data
        self.file_path = file_path

    def __str__(self):
        return f"<Patch:{' file='+str(self.file_path) if self.file_path else ''} {self.patch_hash}>"

    def __repr__(self):
        return self.__str__()
    
    def __hash__(self) -> int:
        return hash(self.patch_hash)
    
    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Patch):
            return False
        
        return self.patch_hash == value.patch_hash

    @classmethod
    def from_git_diff(cls, file_path: Path) -> "Patch":
        with open(file_path, "r") as fp:
            patch_set = PatchSet(fp)

        with open(file_path, "r") as fp:
            diff = fp.read()

        # we only support single patches
        assert len(patch_set) == 1
        patch_data: PatchedFile = patch_set[0]

        target_file = patch_data.path
        func = None
        for hunk in patch_data:
            # TODO: we assume only one function is changed, maybe fix that
            func = hunk.section_header.split(" ")[-1]

        poi = ProgramPOI(target_file, func)
        return cls(poi, diff=diff, patched_file_data=patch_data, file_path=file_path)
