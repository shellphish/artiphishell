import logging
import re
from pathlib import Path
from typing import Optional, List

from unidiff import PatchSet, PatchedFile

from .patched_function import PatchedFunction
from ..utils import md5_hash

_l = logging.getLogger(__name__)


class Patch:
    def __init__(
        self,
        patched_functions: List[PatchedFunction],
        reasoning: Optional[str] = None,
        # useful for ranking purposes (and for testing)
        diff: Optional[str] = None,
        file_path: Optional[Path] = None,
        patched_set_data: Optional[PatchedFile | PatchSet] = None,
        metadata: Optional[dict] = None,
    ):
        def normalize(hash_data: bytes) -> bytes:
            text = hash_data.decode(errors="ignore")
            text = re.sub(r'//.*', '', text)
            text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
            text = re.sub(r'\s+', '', text)
            return text.encode()
        self.patched_functions = sorted(patched_functions, key=lambda x: x.function_name)
        self.reasoning = reasoning
        self.metadata = metadata or {}

        all_new_code = ""
        for patched_func in patched_functions:
            if patched_func.new_code:
                all_new_code += patched_func.new_code
                all_new_code += "\n"
        self.all_new_code = all_new_code

        if all_new_code:
            hash_data = all_new_code.encode()
        elif diff:
            hash_data = diff.encode()
        else:
            hash_data = b""
            _l.warning("No data to hash for patch, this is likely a bad Patch object")

        hash_data = normalize(hash_data)

        # TODO: I'd like to put back fuzzy hashing at some point!
        self.patch_hash = md5_hash(hash_data)

        # for caching purposes
        self.diff = diff or None
        self.patched_set_data = patched_set_data
        self.file_path = file_path
    
    def __str__(self):
        return f"<Patch:{' file='+str(self.file_path) if self.file_path else ''} {self.patch_hash}>"

    def __repr__(self):
        return self.__str__()
    
    def __hash__(self) -> int:
        return hash(self.patch_hash + (str(self.file_path) if self.file_path else ""))

    
    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Patch):
            return False
        
        return self.patch_hash == value.patch_hash

    @classmethod
    def from_git_diff(cls, file_path: Path, metadata: dict | None = None) -> "Patch":
        with open(file_path, "r") as fp:
            patch_set = PatchSet(fp)

        with open(file_path, "r") as fp:
            diff = fp.read()

        # Iterate through all the patched files
        patched_funcs = []
        for patched_file in patch_set:
            target_file = patched_file.path
            functions = set()

            for hunk in patched_file:
                section_header = hunk.section_header
                if section_header:
                    # Extract function name from the section header (adjust split if needed)
                    if "(" in section_header:
                        # Handle cases where function name might include parameters
                        func_name = section_header.split("(")[0].strip()
                    else:
                        func_name = section_header.split(" ")[-1]
                    functions.add(func_name)
            for func in functions:
                # these functions don't need code since we pass patched_set_data to the Patch object
                patched_funcs.append(
                    PatchedFunction(function_name=func, file=target_file)
                )

        # patched pois from diff don't have old/new code, will see if they are needed
        return cls(patched_funcs, diff=diff, patched_set_data=patch_set, file_path=file_path, metadata=metadata)
