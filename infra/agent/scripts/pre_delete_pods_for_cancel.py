#! /usr/bin/env python3

import sys
import os

import argparse
import concurrent.futures
import datetime as _dt
import json
import logging
import subprocess
from typing import List, Tuple, Dict, Any

"""
This script will be run a few min before task cancel to bring down a large number of pods
which slow down the actual pdt task cancellation.

Here is how it works.
We have a CRS_TASK_NUM env which tells us which PDT instance we are running on.
We have a list of the specific tasks we want to bring down early.

When this runs:
- it gets a list of all pods
- it filters that list to only pods starting with `artiphishell-<CRS_TASK_NUM>-`
- it filters out pods with `-set-` in the name (container sets)
- it filters out pods which are younger than 10 minutes

Then it goes through and in a reasonable parallel level it issues kubectl pod delete --force on the pods

It does this with nice logging so we have a record of what it did.
"""


def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """Run *cmd* returning (returncode, stdout, stderr).

    Uses text mode and strips trailing whitespace from stdout/stderr for easier
    logging.
    """
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


class Pod:
    """Light-weight representation of a Kubernetes pod we may delete."""

    __slots__ = ("namespace", "name", "creation_timestamp")

    def __init__(self, namespace: str, name: str, creation_timestamp: str):
        self.namespace = namespace
        self.name = name
        self.creation_timestamp = creation_timestamp  # RFC3339

    # ---------------------------------------------------------------------
    # Derived helpers
    # ---------------------------------------------------------------------
    @property
    def age_minutes(self) -> float:
        try:
            ts = _dt.datetime.strptime(self.creation_timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=_dt.timezone.utc
            )
        except ValueError:
            # Fallback to ISO format that includes fractional seconds or timezone offset
            ts = _dt.datetime.fromisoformat(self.creation_timestamp.rstrip("Z")).replace(
                tzinfo=_dt.timezone.utc
            )
        return (_dt.datetime.now(tz=_dt.timezone.utc) - ts).total_seconds() / 60.0

    # ---------------------------------------------------------------------
    def __repr__(self) -> str:  # noqa: D401
        return f"{self.namespace}/{self.name} (created {self.creation_timestamp})"


# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------

# Only pods that include one of these task identifiers in their name will be
# considered for deletion.  Kubernetes pod names use hyphens, so underscores
# in the identifiers are translated to hyphens for matching purposes.

ALLOWED_TASKS: List[str] = [
    "aflpp_fuzz",
    "aijon_fuzz",
    "corpus_inference_llm",
    "coverage_trace",
    "crash_exploration",
    "diffguy",
    "discovery_guy",
    "dyva_agent",
    "grammar_agent",
    "grammar_composer",
    "grammar_guy",
    "grammarroomba",
    "jazzer_fuzz",
    "kumushi",
    "libfuzzer_fuzz",
    "oss_fuzz_project_build",
    "patch_patrol",
    "pov_patrol",
    "patcherq",
    "patchery",
    "poiguy",
    "povguy",
    "ron_composer",
    "scan_guy",
]

# Convert to hyphen-separated patterns once at import time
_ALLOWED_PATTERNS = [t.replace("_", "-") for t in ALLOWED_TASKS]


# -------------------------------------------------------------------------
# Helper utilities
# -------------------------------------------------------------------------

def _is_name_allowed(name: str) -> bool:
    """Return True if *name* contains one of the allowed task identifiers."""
    for pat in _ALLOWED_PATTERNS:
        if pat in name:
            return True
    return False


# -------------------------------------------------------------------------
# Core logic
# -------------------------------------------------------------------------

def gather_pods(prefix: str, min_age_min: int) -> List[Pod]:
    """Gather pods from the cluster that match the criteria.

    Parameters
    ----------
    prefix:
        The required prefix for pod names.
    min_age_min:
        Minimum age in minutes a pod must have before we consider deleting it.
    """
    rc, out, err = _run(["kubectl", "get", "pods", "-n", "default", "-o", "json"])
    if rc != 0:
        logging.error("Failed to list pods: %s", err or "<no stderr>")
        sys.exit(1)

    try:
        data: Dict[str, Any] = json.loads(out)
    except json.JSONDecodeError as exc:
        logging.error("Could not parse kubectl JSON output: %s", exc)
        sys.exit(1)

    pods: List[Pod] = []
    for item in data.get("items", []):
        metadata = item.get("metadata", {})
        name: str = metadata.get("name", "")
        if not name.startswith(prefix):
            continue
        if "-set-" in name:
            # Skip container set pods
            continue
        if not _is_name_allowed(name):
            # Not in allow list
            continue

        ts = (
            metadata.get("creationTimestamp")
            or item.get("status", {}).get("startTime")
            or ""
        )
        if not ts:
            continue

        pod = Pod(metadata.get("namespace", "default"), name, ts)
        if pod.age_minutes < min_age_min:
            continue
        pods.append(pod)

    return pods


def delete_pod(pod: Pod, dry_run: bool = False) -> bool:
    """Attempt to delete *pod*.  Returns True on success.

    If *dry_run* is true, simulates deletion without calling kubectl.
    """
    if dry_run:
        logging.info("[dry-run] Would delete pod %s", pod)
        return True

    cmd = [
        "kubectl",
        "delete",
        "pod",
        pod.name,
        "-n",
        pod.namespace,
        "--force",
        "--grace-period=0",
        "--ignore-not-found",
    ]
    rc, out, err = _run(cmd)
    if rc == 0:
        logging.info("Deleted pod %s", pod)
        if out:
            logging.debug(out)
        return True
    else:
        logging.warning("Failed to delete pod %s: %s", pod, err or out)
        return False


# -------------------------------------------------------------------------
# CLI entry-point
# -------------------------------------------------------------------------

def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Pre-delete artiphishell worker pods to speed up task cancellation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not actually delete pods, just print what would happen.",
    )
    parser.add_argument(
        "--min-age-minutes",
        type=int,
        default=10,
        help="Only delete pods older than this many minutes.",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=20,
        help="Maximum concurrent kubectl deletions to issue.",
    )

    args = parser.parse_args(argv)

    crs_task_num = os.environ.get("CRS_TASK_NUM")
    if not crs_task_num:
        logging.error("CRS_TASK_NUM environment variable is not set; nothing to do.")
        sys.exit(1)

    prefix = f"artiphishell-{crs_task_num}-"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logging.info(
        "Gathering pods with prefix '%s' older than %d min (dry-run=%s)...",
        prefix,
        args.min_age_minutes,
        args.dry_run,
    )

    pods_to_delete = gather_pods(prefix, args.min_age_minutes)

    if not pods_to_delete:
        logging.info("No pods matched criteria; exiting.")
        return

    logging.info("Found %d pods to delete", len(pods_to_delete))

    success = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
        fut_to_pod = {pool.submit(delete_pod, p, args.dry_run): p for p in pods_to_delete}
        for fut in concurrent.futures.as_completed(fut_to_pod):
            pod = fut_to_pod[fut]
            try:
                ok = fut.result()
            except Exception as exc:  # pylint: disable=broad-except
                logging.error("Exception while deleting pod %s: %s", pod, exc)
                continue
            if ok:
                success += 1

    logging.info("Successfully deleted %d/%d pods", success, len(pods_to_delete))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)

