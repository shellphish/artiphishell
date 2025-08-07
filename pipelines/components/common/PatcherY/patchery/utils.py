import hashlib
import logging
from typing import Union, Optional
from pathlib import Path
from typing import List

import git

from .data.program_poi import ProgramPOI
import os

import tlsh

_l = logging.getLogger(__name__)

class WorkDirContext:
    def __init__(self, path: Path):
        self.path = path
        self.origin = Path(os.getcwd()).absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.origin)


def read_src_from_file(src_file, start_line, end_line, backup_code=None):
    src_file = Path(src_file).absolute()
    if start_line is None or end_line is None or not src_file.exists():
        if backup_code is None:
            _l.warning("Attempted to use backup code for a POI, but it is also None!")
        return backup_code

    with open(src_file, "r") as f:
        lines = f.readlines()
    
    return "".join(lines[start_line-1:end_line])


def find_src_root_from_commit(target_root: Path, commit: str) -> Optional[Path]:
    if commit is None:
        return None

    target_root = Path(target_root).absolute()
    target_src = (target_root / "src").absolute()
    if not target_src.exists():
        return None

    # find every git repo in the target_src folder
    for git_path in target_src.rglob(".git"):
        git_repo_path = git_path.parent.absolute()
        try:
            repo = git.Repo(git_repo_path)
        except git.exc.InvalidGitRepositoryError:
            continue

        # check if the commit exists anywhere in the repo
        if commit in repo.git.rev_list("HEAD"):
            return git_repo_path

    return None


#
# Hashing
#

def md5_hash(bstring: bytes) -> str:
    hasher = hashlib.md5()
    hasher.update(bstring)
    return hasher.hexdigest()


def fuzzy_hash(bstring: bytes, force=True) -> str:
    if len(bstring) < 50:
        if not force:
            raise ValueError("String is too short for fuzzy hashing.")

        remainder = 50 - len(bstring)
        for i in range(remainder):
            bstring += str(i).encode()
            if len(bstring) >= 50:
                break

    hasher = tlsh.Tlsh()
    hasher.update(bstring)
    hasher.final()
    return hasher.hexdigest()


def compare_hashes(hash1: str, hash2: str, normalize=True) -> Union[int, float]:
    score = tlsh.diff(hash1, hash2)
    if normalize:
        score = _normalize_hash_score(score)

    return score


def absolute_path_finder(src_root: Path, relative_file_path: Path) -> Path:
    if os.path.exists(src_root / relative_file_path):
        return src_root / relative_file_path
    poi_src_name = os.path.basename(relative_file_path)
    for dirpath, dirnames, filenames in os.walk(src_root):
        if poi_src_name in filenames:
            poi_src_name_match = os.path.join(dirpath, poi_src_name)
            if type(relative_file_path) != str:
                relative_file_path = str(relative_file_path)
            if poi_src_name_match[-len(relative_file_path) :] == relative_file_path:
                return Path(poi_src_name_match)
    return None


def pois_filepath_abs(src_root: Path, pois: List[ProgramPOI]) -> List[ProgramPOI]:
    for poi in pois:
        if not os.path.isabs(poi.file):
            poi.file = absolute_path_finder(src_root, poi.file)
    return pois


def _normalize_hash_score(score: int):
    return max(0, (300 - score) // 3)


LLM_MAPPING = {
    "oai-gpt-4-turbo": "gpt-4-turbo-2024-04-09",
    "oai-gpt-4": "gpt-4-0613",
    "oai-gpt-4o": "gpt-4o-2024-05-13",
    "claude-3.5-sonnet": "claude-3-5-sonnet-20240620",
}


def llm_cost(model_name: str, prompt_tokens: int, completion_tokens: int):
    # these are the $x per Million tokens
    cost = {
        "oai-gpt-4-turbo": {"prompt_price": 10, "completion_price": 30},
        "oai-gpt-4": {"prompt_price": 30, "completion_price": 60},
        "oai-gpt-4o": {"prompt_price": 5, "completion_price": 15},
        "claude-3.5-sonnet": {"prompt_price": 3, "completion_price": 15},
    }
    llm_price = cost[model_name]
    prompt_price = (prompt_tokens / 1000000) * llm_price["prompt_price"]
    completion_price = (completion_tokens / 1000000) * llm_price["completion_price"]

    return round(prompt_price + completion_price, 5)
