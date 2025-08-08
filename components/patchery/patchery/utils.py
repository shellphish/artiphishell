import hashlib
import logging
import time
from typing import Union, Optional
from pathlib import Path
from typing import List

from crs_telemetry.utils import get_current_span

import git

from kumushi.data import PoI
import os

import tlsh

_l = logging.getLogger(__name__)

MULTITHREAD_LOG_FOLDER_BASE = '/tmp/patchery/thread_logs'


class WorkDirContext:
    def __init__(self, path: Path):
        self.path = path
        self.origin = Path(os.getcwd()).absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.origin)


def get_new_logging_dir() -> Path:
    # create a new directory for logging
    if not os.path.exists(MULTITHREAD_LOG_FOLDER_BASE):
        os.makedirs(MULTITHREAD_LOG_FOLDER_BASE)

    # get the current time (unix)
    timestamp = str(int(time.time()))

    # create a new directory with the timestamp
    new_dir = os.path.join(MULTITHREAD_LOG_FOLDER_BASE, timestamp)
    os.makedirs(new_dir)

    return Path(new_dir)


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

    return score / 100


def absolute_path_finder(src_root: Path, relative_file_path: Path) -> Path | None:
    if os.path.exists(src_root / relative_file_path):
        return src_root / relative_file_path

    poi_src_name = os.path.basename(relative_file_path)
    # attempt resolving by seeing the overlap of the file name
    for dirpath, dirnames, filenames in os.walk(src_root):
        if poi_src_name in filenames:
            poi_src_name_match = os.path.join(dirpath, poi_src_name)
            if not isinstance(relative_file_path, str):
                relative_file_path = str(relative_file_path)
            if poi_src_name_match[-len(relative_file_path) :] == relative_file_path:
                return Path(poi_src_name_match)

    # attempt a hack of finding the start of src and then checking if it exists on the source root
    # find 'src' in the path, and truncate everything before it
    relative_file_path = Path(relative_file_path)
    path_parts = list(relative_file_path.parts)
    if "src" in path_parts:
        src_index = path_parts.index("src")
        new_rel_path = Path("/".join(relative_file_path.parts[src_index:]))
        full_path = src_root / new_rel_path
        if full_path.exists():
            _l.critical(
                f"Found the file by hacking the path: %s! Clang Indexer likely failed earlier!",
                relative_file_path
            )
            return full_path

    return None


def pois_filepath_abs(src_root: Path, pois: List[PoI]) -> List[PoI]:
    # TODO: update this later, maybe this can be deprecated?
    return pois


def _normalize_hash_score(score: int):
    return max(0, (300 - score) // 3)


LLM_MAPPING = {
    "gpt-4o": "gpt-4o",
    "claude-3.5-sonnet": "claude-3.5-sonnet",
    "claude-3.7-sonnet": "claude-3.7-sonnet",
    "o3-mini": "o3-mini",
    "oai-gpt-o3-mini": "o3-mini",
    'o4-mini': 'o4-mini',
    'oai-gpt-o4-mini': 'o4-mini',
    'o3': 'o3',
    'oai-gpt-o3': 'o3',
    'gpt-4.1': 'gpt-4.1',
    'claude-4-sonnet': 'claude-4-sonnet',
}


def llm_model_name(model: str = "", agentlib = False) -> str:
    if model.strip() == "":
        model = os.getenv("LLM_MODEL_NAME", "claude-3.7-sonnet")
        return LLM_MAPPING.get(model)
    if model not in LLM_MAPPING.keys():
        raise ValueError(f"Invalid LLM model name: {model}, you should use one of {LLM_MAPPING.keys()}")
    if agentlib:
        return model
    return LLM_MAPPING.get(model)


def llm_cost(model_name: str, prompt_tokens: int, completion_tokens: int, cached_prompt_tokens: int = 0):
    # these are the $x per Million tokens
    cost = {
        "oai-gpt-4-turbo": {"prompt_price": 10, "completion_price": 30},
        "oai-gpt-4": {"prompt_price": 30, "completion_price": 60},
        "oai-gpt-4o": {"prompt_price": 2.5, "cached_prompt_price": 1.25, "completion_price": 10},
        "oai-gpt-o1-preview": {"prompt_price": 15, "cached_prompt_price": 7.5, "completion_price": 60},
        "oai-gpt-o3-mini": {"prompt_price": 1.1, "cached_prompt_price": 0.55, "completion_price": 4.4},
        "claude-3-5-sonnet-20241022": {"prompt_price": 3, "completion_price": 15},
        "claude-3-7-sonnet-20250219": {"prompt_price": 3, "completion_price": 15},
    }
    llm_price = cost.get(model_name, cost.get(f'oai-{model_name}'))
    prompt_price = ( (prompt_tokens - cached_prompt_tokens) / 1000000) * llm_price["prompt_price"]
    completion_price = (completion_tokens / 1000000) * llm_price["completion_price"]
    cached_prompt_price = (cached_prompt_tokens / 1000000) * llm_price.get("cached_prompt_price", 0)
    cost = round(prompt_price + completion_price + cached_prompt_price, 5)

    span = get_current_span()
    span.set_attributes({"gen_ai.request.model": model_name,
    "gen_ai.usage.input_tokens": prompt_tokens,
    "gen_ai.usage.output_tokens": completion_tokens,
    "gen_ai.usage.cached_read_tokens": cached_prompt_tokens,
    "gen_ai.usage.total_tokens": prompt_tokens + completion_tokens,
    "gen_ai.usage.cost_prompt": prompt_price,
    "gen_ai.usage.cost_completion": completion_price,
    "gen_ai.usage.cost": prompt_price + completion_price + cached_prompt_price,
    })
    return cost
