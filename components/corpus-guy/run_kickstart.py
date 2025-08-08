import argparse
import logging
import os
import shutil
import subprocess
import zipfile

from pathlib import Path
from difflib import SequenceMatcher
from typing import Optional, List, Tuple

from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel("corpus-guy-kickstart", "input_generation", "corpus_selection")
TRACER = get_otel_tracer()

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("corpusguy")

# Load environment variables
LANGUAGE = os.environ.get("LANGUAGE")
ARTIPHISHELL_PROJECT_NAME = os.environ.get("ARTIPHISHELL_PROJECT_NAME")
ARTIPHISHELL_HARNESS_NAME = os.environ.get("ARTIPHISHELL_HARNESS_NAME")
INPUT_CORPUS_KICKSTART_PATH = os.environ.get("INPUT_CORPUS_KICKSTART_PATH")
ARTIPHISHELL_FUZZER_SYNC_KICKSTART = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_KICKSTART")
CORPUSGUY_SYNC_TO_FUZZER = os.environ.get("CORPUSGUY_SYNC_TO_FUZZER")
ARTIPHISHELL_MAX_SEEDS_TOTAL = int(os.environ.get("ARTIPHISHELL_MAX_SEEDS_TOTAL"))

MIN_PROJECT_NAME_SIMILARITY = 0.8
MIN_HARNESS_NAME_SIMILARITY = 0.9
MAX_PROJECT_CANDIDATES = 3

ARTIPHISHELL_FUZZER_SYNC_KICKSTART = Path(ARTIPHISHELL_FUZZER_SYNC_KICKSTART)
INPUT_CORPUS_KICKSTART_PATH = Path(INPUT_CORPUS_KICKSTART_PATH)
INPUT_CORPUS_KICKSTART_PATH = INPUT_CORPUS_KICKSTART_PATH / ("jvm" if LANGUAGE == "jvm" else "c")

log.info(f"LANGUAGE: {LANGUAGE}")
log.info(f"ARTIPHISHELL_PROJECT_NAME: {ARTIPHISHELL_PROJECT_NAME}")
log.info(f"ARTIPHISHELL_HARNESS_NAME: {ARTIPHISHELL_HARNESS_NAME}")
log.info(f"INPUT_CORPUS_KICKSTART_PATH: {INPUT_CORPUS_KICKSTART_PATH}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_KICKSTART: {ARTIPHISHELL_FUZZER_SYNC_KICKSTART}")
log.info(f"CORPUSGUY_SYNC_TO_FUZZER: {CORPUSGUY_SYNC_TO_FUZZER}")
log.info(f"MIN_PROJECT_NAME_SIMILARITY: {MIN_PROJECT_NAME_SIMILARITY}")
log.info(f"MIN_HARNESS_NAME_SIMILARITY: {MIN_HARNESS_NAME_SIMILARITY}")
log.info(f"MAX_PROJECT_CANDIDATES: {MAX_PROJECT_CANDIDATES}")
log.info(f"ARTIPHISHELL_MAX_SEEDS_TOTAL: {ARTIPHISHELL_MAX_SEEDS_TOTAL}")


def _sim(a: str, b: str) -> float:
    """Return SequenceMatcher ratio between two strings."""
    return SequenceMatcher(None, a, b).ratio()

def find_project_dirs(
    search_dir: Path,
    project_query: str,
    min_similarity: float,
    max_candidates: int
) -> List[str]:
    """
    Return a list of project names under `search_dir` matching `project_query`:
    - If there is an exact match, returns [exact_name].
    - Otherwise returns up to `max_candidates` fuzzy matches (ratio >= min_similarity),
      ordered by descending similarity.
    - Returns [] if nothing matches.
    """
    candidates = [p.name for p in search_dir.iterdir() if p.is_dir()]
    # exact match, case-insensitive
    for name in candidates:
        if name.lower() == project_query.lower():
            return [name]
    # fuzzy matches on lowercase
    lquery = project_query.lower()
    scored = [
        (name, _sim(lquery, name.lower()))
        for name in candidates
        if _sim(lquery, name.lower()) >= min_similarity
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [name for name, _ in scored][:max_candidates]

def find_harness_with_score(
    project_dir: Path,
    harness_query: str
) -> Tuple[Optional[str], float]:
    """
    Returns (best_harness_name, score) for subdirs under project_dir:
    - Exact match -> score == 1.0
    - Otherwise the subdir with highest SequenceMatcher ratio
    - If no subdirs, returns (None, 0.0)
    """
    subdirs = [p.name for p in project_dir.iterdir() if p.is_dir()]
    if not subdirs:
        return None, 0.0

    # exact match
    if harness_query in subdirs:
        return harness_query, 1.0

    # best fuzzy match
    best_name, best_score = max(
        ((d, _sim(harness_query, d)) for d in subdirs),
        key=lambda x: x[1]
    )
    return best_name, best_score

def find_all_projects_by_harness(
    search_dir: Path,
    harness_query: str,
    min_similarity: float
    ) -> List[Tuple[str, str, float]]:
    """
    Scan every project under `search_dir`:
      - run find_harness_with_score()
      - if score >= min_similarity, include (project, best_harness, score)
    Returns sorted list by descending score.
    """
    results: List[Tuple[str, str, float]] = []
    for proj_path in search_dir.iterdir():
        if not proj_path.is_dir():
            continue
        harness, score = find_harness_with_score(proj_path, harness_query)
        if harness and score >= min_similarity:
            results.append((proj_path.name, harness, score))
    results.sort(key=lambda x: x[2], reverse=True)
    return results

@TRACER.start_as_current_span("corpus-guy-kickstart.extract_to_output")
def extract_to_output(
    search_dir: Path,
    project_name: str,
    harness_name: str,
    output_dir: Path
) -> None:
    source_dir = search_dir / project_name / harness_name
    extraction_dir = output_dir / ".tmp" / project_name / harness_name
    extraction_dir.mkdir(parents=True, exist_ok=True)

    if CORPUSGUY_SYNC_TO_FUZZER.lower() not in ["1", "true", "t", "yes", "y"]:
        log.info(f"Skipping extraction of seeds for {harness_name=} and {project_name=} to {output_dir=}")
        return

    elif not source_dir.is_dir():
        log.warning(f"Source path '{source_dir}' does not exist or unsupported")
        return
    
    log.info(f"Extracting seeds for {harness_name=} and {project_name=} to {output_dir=}")
    for zip_path in source_dir.glob("*.zip"):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extraction_dir)
            log.info(f"Extracted '{zip_path}' into '{extraction_dir}'")
        except zipfile.BadZipFile:
            log.warning(f"Bad zip file: {zip_path}")

@TRACER.start_as_current_span("corpus-guy-kickstart.main")
def main():
    # FIND PROJECT NAME CANDIDATES
    project_name_candidates = find_project_dirs(INPUT_CORPUS_KICKSTART_PATH, ARTIPHISHELL_PROJECT_NAME, MIN_PROJECT_NAME_SIMILARITY, MAX_PROJECT_CANDIDATES)
    log.info(f"Project name candidates: {project_name_candidates}")

    # IF ANY, LOOK FOR HARNESSES IN THOSE PROJECTS
    if project_name_candidates:
        for project_name in project_name_candidates:
            # look for harnesses in the project
            harness_name, score = find_harness_with_score(INPUT_CORPUS_KICKSTART_PATH / project_name, ARTIPHISHELL_HARNESS_NAME)
            if harness_name and score >= MIN_HARNESS_NAME_SIMILARITY:
                log.info(f"Found harness '{harness_name}' with score {score} in project '{project_name}'")
                # copy project-harness pair to output
                extract_to_output(INPUT_CORPUS_KICKSTART_PATH, project_name, harness_name, ARTIPHISHELL_FUZZER_SYNC_KICKSTART)
            else:
                log.info(f"Ignoring harness '{harness_name}' with score {score} in project '{project_name}'")

    # ELSE, ASSUME THAT THE PROJECT NAME WAS CHANGED: LOOK FOR HARNESSES IN ALL PROJECTS
    else:
        log.info(f"No project candidates found by name '{ARTIPHISHELL_PROJECT_NAME}'")
        for project_name, harness_name, score in find_all_projects_by_harness(INPUT_CORPUS_KICKSTART_PATH, ARTIPHISHELL_HARNESS_NAME, MIN_HARNESS_NAME_SIMILARITY):
            if harness_name and score >= MIN_HARNESS_NAME_SIMILARITY:
                log.info(f"Found harness '{harness_name}' with score {score} in project '{project_name}'")
                # copy project-harness pair to output
                extract_to_output(INPUT_CORPUS_KICKSTART_PATH, project_name, harness_name, ARTIPHISHELL_FUZZER_SYNC_KICKSTART)
            else:
                log.info(f"Ignoring harness '{harness_name}' with score {score} in project '{project_name}'")

    # FLATTEN ALL SEEDS TO OUTPUT_DIR
    log.info(f"Flattening all seeds to output dir: {ARTIPHISHELL_FUZZER_SYNC_KICKSTART}")

    # Delete all but $ARTIPHISHELL_MAX_SEEDS_TOTAL random files
    subprocess.run(f'cd {ARTIPHISHELL_FUZZER_SYNC_KICKSTART} && find . -mindepth 2 -type f | shuf | tail -n +{ARTIPHISHELL_MAX_SEEDS_TOTAL + 1} | xargs rm -f', shell=True, check=True, executable='/bin/bash')

    cmd = f'cd {ARTIPHISHELL_FUZZER_SYNC_KICKSTART} && i=1 && find . -mindepth 2 -type f | while read file; do mv "$file" "./id:$(printf %06d $i)_${{file##*/}}" && ((i++)); done'
    log.info(f"Running command: {cmd}")
    subprocess.run(cmd, shell=True, check=True, executable='/bin/bash')

    num_seeds = len(list(ARTIPHISHELL_FUZZER_SYNC_KICKSTART.glob("id:*")))
    log.info(f"Flattened {num_seeds} seeds to output dir: {ARTIPHISHELL_FUZZER_SYNC_KICKSTART}")

    # REMOVE .TMP DIR
    log.info(f"Removing temporary directory: {ARTIPHISHELL_FUZZER_SYNC_KICKSTART / '.tmp'}")
    shutil.rmtree(ARTIPHISHELL_FUZZER_SYNC_KICKSTART / ".tmp", ignore_errors=True)

if __name__ == "__main__":
    main()
