#!/usr/bin/env python3
import argparse
import os
import subprocess
import logging
import pprint
import time
from pathlib import Path
from typing import List, Dict

import git
import yaml

from shellphish_crs_utils.challenge_project import ChallengeProject
from rich.logging import RichHandler
from rich.console import Console

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)]
)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def get_commits(repo_dir: Path):
    repo = git.Repo(repo_dir)
    repo.git.execute(["git", "config", "--global", "--add", "safe.directory", str(repo_dir)])
    commits = [str(commit) for commit in repo.iter_commits()]
    print(f"Get Commits: {repo_dir=} {commits=}")
    return commits


def find_first_crashing_commits(
    cp: ChallengeProject, working_dir: Path, crash_input_path: Path, harness_name: str, sanitizer_ids: List[str]) -> Dict[str, Dict[str, List[str]]]:
    crashing_commits = {}
    found_one_crash = False
    # find the first crashing commit for each source repo
    for sanitizer_id in sanitizer_ids:
        for cp_source in cp.cp_sources:
            actual_crashing_commit = None
            log.info("Testing CP Source: %s", cp_source)
            commits = get_commits(cp.project_path / "src" / cp_source.key)
            log.info("We have %s commits", len(commits))
            if len(commits) == 1:
                log.critical("Only one commit %s", commits[0])
                continue
            latest, oldest = 0, len(commits) - 1
            while latest <= oldest:
                mid = (latest + oldest) // 2
                log.info("Searching Latest: %s, Mid: %s, Oldest: %s", latest, mid, oldest)
                log.info("CMD: %s", ' '.join(["rsync", "-ra", "--delete", str(cp.project_path) + '/', str(working_dir) + '/']))

                # Copy and set user for dubious ownership
                subprocess.run(["/usr/bin/rsync", "-ra", "--delete", str(cp.project_path) + '/', str(working_dir) + '/'])
                subprocess.run(["/usr/bin/chown", "-R", "root:root",  str(working_dir) + '/'])

                commit_cp = ChallengeProject(working_dir)
                commit_cp.checkout_commit(commits[mid])

                log.info("ATTEMPTING: %s", commits[mid])
                if check_if_crashes(commit_cp, crash_input_path, harness_name, working_dir, sanitizer_id):
                    log.info("CRASHING!!! %s", commits[mid])
                    if mid != len(commits) - 1: #0-day???
                        actual_crashing_commit = commits[mid]
                    latest = mid + 1
                else:
                    log.info("NON-CRASHING!!! %s", commits[mid])
                    oldest = mid - 1
                log.info("New Values: %s, Mid: %s, Oldest: %s", latest, mid, oldest)

            if actual_crashing_commit:
                if cp_source.key not in crashing_commits:
                    crashing_commits[cp_source.key] = {actual_crashing_commit: []}
                crashing_commits[cp_source.key][actual_crashing_commit].append(sanitizer_id)
                found_one_crash = True


    if not found_one_crash:
        log.error("No crashing commit found")
        return {}

    log.critical(f"CRASHING COMMITS!!!!!! {crashing_commits}")
    return crashing_commits

def check_if_crashes(commit_cp: ChallengeProject, crash_input_path: Path, harness_name: str, working_dir: str, sanitizer_id: str):
    log.info("Testing Crash: %s %s %s", commit_cp.project_path, crash_input_path, harness_name)
    log.info("Building Project")
    while commit_cp.build()["exitcode"] != 0:
        log.critical("BUILD FAILED OH NO")
        subprocess.run(["/usr/bin/rsync", "-ra", "--delete", str(cp.project_path) + '/', str(working_dir) + '/'])
        subprocess.run(["/usr/bin/chown", "-R", "root:root",  str(working_dir) + '/'])
    log.info("Running PoV")
    log.debug("SEED PATH: %s", crash_input_path)
    log.debug("SEED: %s", crash_input_path.read_bytes())
    pov = commit_cp.run_pov(harness_name, data_file=crash_input_path)
    log.debug("POV: %s", pprint.pformat(pov, indent=4))
    log.critical("%s vs %s", pov["pov"]["triggered_sanitizers"], sanitizer_id)
    return sanitizer_id in pov["pov"]["triggered_sanitizers"]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Find the first commit that causes a crash"
    )
    parser.add_argument("--cp-repo", type=Path, help="The path to the cp git repository")
    parser.add_argument("--working-dir", type=Path, help="The path to the shared dir to work out of")
    parser.add_argument("--crash-input-path", type=Path, help="The path to the crash input")
    parser.add_argument("--crash-input-id", type=str, help="Pydatatask ID of the crashing input")
    parser.add_argument("--crash-input-meta", type=Path, help="The metadata associated with the crashing seed")
    parser.add_argument("--output", type=Path, help="The path to the output directory")
    parser.add_argument("--output-dedup", type=Path, help="The path to the deduped output directory")

    args = parser.parse_args()

    cp = ChallengeProject(args.cp_repo)
    with args.crash_input_meta.open("r") as f:
        crash_metadata = yaml.safe_load(f)
    harness_name = crash_metadata["cp_harness_name"]
    harness_id = crash_metadata["cp_harness_id"]
    orig_sanitizer_ids = crash_metadata["consistent_sanitizers"]
    crash_report_id = crash_metadata["crash_report_id"]
    crashing_commits = find_first_crashing_commits(cp, args.working_dir, args.crash_input_path, harness_name, orig_sanitizer_ids)
    count = 0
    for source, commit_dict in crashing_commits.items():
        for commit, sanitizer_ids in commit_dict.items():
            commit_report = {"cp_source": source,
                             "crashing_commit": commit,
                             "sanitizer_ids": sorted(list(set(sanitizer_ids))),
                             "crash_report_id": crash_report_id,
                             "crash_id": args.crash_input_id,
                             "harness_id": harness_id}
            # crashing_commit.cp_source         => the entry in `sources` which houses the crashing commit
            # crashing_commit.crashing_commit   => introducing commit hash
            # crashing_commit.sanitizer_ids     => sorted list of sanitizers triggering in this commit
            # crashing_commit.crash_id          => representative_crashing_harness_inputs/poi_report/pov_report/asan2report
            # crashing_commit.crash_report_id   => the crash report id (representative_crashing_harness_inputs/poi_report/pov_report/asan2report)
            # crashign_commit.harness_id        => the CP harness id (the `id_1` shit
            
            count += 1
            log.info(f"Writing to %s: %s", args.output / str(count), commit_report)
            with open(args.output / str(count), "w") as f:
                yaml.safe_dump(commit_report, f)
            with open(args.output_dedup / str(count), "w") as f:
                yaml.safe_dump({"crashing_commit": commit, "sanitizer_ids": commit_report["sanitizer_ids"], "harness_id": harness_id, "target_id": crash_metadata["target_id"]}, f)
