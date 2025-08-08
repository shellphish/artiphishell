from pathlib import Path
from typing import List

def get_target_irrelevant_container_src_paths() -> List[Path]:
    return [Path(p) for p in (
        '/src/aflplusplus',
        '/src/honggfuzz',
        '/src/libfuzzer',
        '/src/centipede',

        # common target-included folders we don't really care about
        '/src/libprotobuf-mutator',
        '/src/fuzzer-test-suite',
        '/src/LPM',

        '/src/shellphish')
    ]

def is_target_path_irrelevant(path: Path, focus_repo_path: Path) -> bool:
    """
    Check if the given path is irrelevant for the target.
    """
    if path.resolve().is_relative_to(focus_repo_path.resolve()):
        return False
    irrelevant_paths = get_target_irrelevant_container_src_paths()
    return any(path.is_relative_to(irrelevant_path) for irrelevant_path in irrelevant_paths)