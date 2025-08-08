import argparse
import math
from dataclasses import dataclass, field
import functools
import json
import logging
import hashlib
import time
from typing import Iterator, List, Optional, Tuple
from analysis_graph import OrganizerDedupInfoNode
from analysis_graph.models.harness_inputs import HarnessInputNode
import pytz
import yaml
import math
from typing import Tuple, List

import os
import patcherg
from datetime import datetime, timedelta
from pathlib import Path

from shellphish_crs_utils.utils import timed_context
from shellphish_crs_utils.models.crs_reports import POIReport, PatchRequestMeta
from shellphish_crs_utils.models.patch import PatchBypassRequestMeta
from shellphish_crs_utils.pydatatask.client import PDClient
from analysis_graph.api.dedup import GeneratedPatch, PoVReportNode, find_clusters, Cluster
from analysis_graph.models.crashes import BucketNode, PatchergSubmissionNode

#
# Tunable knobs for submission
#

# full (12 hours)
GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_FULL = 60
BUCKET_SLOW_DOWN_AMT_FULL = 12
MAX_IMPERFECT_PATCHES_TOTAL_FULL = 3

# delta (6 hours)
GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_DELTA = 30
BUCKET_SLOW_DOWN_AMT_DELTA = 6
MAX_IMPERFECT_PATCHES_TOTAL_DELTA = 2

TOO_MANY_PATCHES_PER_BUCKETS = 3

# the following values will be updated based on the task, defaulting to full:
# at what value should you start increasing the patch cooking time
BUCKET_SLOW_DOWN_AMT = BUCKET_SLOW_DOWN_AMT_FULL
# how long should we wait before submitting a good patch
GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_FULL
# how long the current wait should be (based on the base)
GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_FULL
# how many imperfect patches should we allow to be submitted in total
MAX_IMPERFECT_PATCHES_TOTAL = MAX_IMPERFECT_PATCHES_TOTAL_FULL
# how long should we wait before submitting a non-perfect patch
NON_PERFECT_PATCH_SUBMISSION_TIMEOUT_MINUTES = 45
NEW_BUCKET_HARNESS_INPUT_SUBMISSION_CUTOFF_MINUTES = 15
# TODO(FINALDEPLOY) Decide if we want to pre-cluster povs or not

#
# Counters
#

SUBMITTED_IMPERFECT_PATCHES = 0

_l = logging.getLogger(__name__)
logging_timed_context = functools.partial(timed_context, _l)

def adjust_task_type_globals(task_type: str):
    global GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES, GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE, BUCKET_SLOW_DOWN_AMT, MAX_IMPERFECT_PATCHES_TOTAL
    if task_type == "full":
        GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_FULL
        GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_FULL
        BUCKET_SLOW_DOWN_AMT = BUCKET_SLOW_DOWN_AMT_FULL
        MAX_IMPERFECT_PATCHES_TOTAL = MAX_IMPERFECT_PATCHES_TOTAL_FULL
    else:
        GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_DELTA
        GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE = GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_DELTA
        BUCKET_SLOW_DOWN_AMT = BUCKET_SLOW_DOWN_AMT_DELTA
        MAX_IMPERFECT_PATCHES_TOTAL = MAX_IMPERFECT_PATCHES_TOTAL_DELTA

def update_good_patch_submission_timeout(cluster_cnt: int) -> int:
    """
    * cluster_cnt < BUCKET_SLOW_DOWN   → baseline timeout
    * cluster_cnt ≥ BUCKET_SLOW_DOWN   → baseline × (1.5 + α · log₂(1 + extra))
      with “extra” = how many clusters we are past the threshold.
    """
    if cluster_cnt < BUCKET_SLOW_DOWN_AMT:
        return GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE

    extra = cluster_cnt - BUCKET_SLOW_DOWN_AMT   # 1-based for nicer math
    a = 0.20                                         # ⇠ dial this down for slower growth
    growth = 1.5 + a * math.log2(1 + extra)          # ⇠ first bump is ×1.5, then slow log rise
    return int(GOOD_PATCH_SUBMISSION_TIMEOUT_MINS_BASE * growth)

def score_patch(patch: GeneratedPatch, cluster: Cluster) -> float:
    """
    Higher is better patch. The range is [0,1]
    """
    try:
        mitigated_in_cluster = len(patch.mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        ).all())
        unmitigated_in_cluster = len(patch.non_mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        ).all())
    except Exception:
        _l.error(f"Error while scoring patch {patch.patch_key} in cluster {cluster}", exc_info=True)
        return 0.0

    total_povs = mitigated_in_cluster + unmitigated_in_cluster
    return bayesian_likelihood_score(mitigated_in_cluster, total_povs)

def bayesian_likelihood_score(k: int, n: int, alpha: float = 1.0, beta: float = 1.0) -> float:
    """
    Bayesian likelihood-style score for a patch that mitigates `k`
    out of `n` vulnerabilities.

    Uses a Beta(alpha, beta) prior (Jeffreys / Laplace smoothing when
    alpha = beta = 1).  The returned score is the posterior mean of the
    mitigation probability, i.e.

        E[p | data] = (k + alpha) / (n + alpha + beta)

    ────────────────────────────────────────────────────────────────
    Properties (with alpha = beta = 1):
        • 3/3 (0.800)  > 2/3 (0.600)
        • 49/50 (0.962) > 3/3 (0.800)
        • 50/50 (0.981) > 3/3 (0.800)
        • 50/50 (0.981) > 49/50 (0.962)
    """
    if n <= 0:
        return 0
    return (k + alpha) / (n + alpha + beta)

def get_current_normalized_time() -> datetime:
    """
    Get the current time in UTC.
    """
    return normalize_time(PoVReportNode.get_current_neo4j_time().replace(tzinfo=pytz.utc))

def get_deadline():
    deadline = os.environ.get('DEADLINE', None)
    if not deadline:
        return None
    # Deadline is in milliseconds since epoch
    return datetime.fromtimestamp(int(deadline) / 1000, tz=pytz.utc)

def normalize_time(dt) -> datetime:
    """
    Normalize the given datetime to UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=pytz.utc)
    return dt.astimezone(pytz.utc)

def get_patch_age(patch: GeneratedPatch):
    return get_current_normalized_time() - normalize_time(patch.time_created)

def is_patch_older_than_minutes(patch: GeneratedPatch, timeout_minutes: int) -> bool:
    age = get_patch_age(patch)

    return age > timedelta(minutes=timeout_minutes)

def will_be_past_deadline(patch: GeneratedPatch, timeout_minutes: int) -> bool:
    patch_t = patch.time_created.replace(tzinfo=pytz.utc)
    deadline = get_deadline()
    if deadline is None:
        return False

    if patch_t + timedelta(minutes=timeout_minutes) > deadline:
        return True
    return False

def is_past_deadline(dt: datetime, timeout_minutes: int, deadline=None) -> bool:
    """
    Check if the given datetime is past the deadline.
    The deadline is defined as the current time plus the timeout minutes.
    """
    if deadline is None:
        deadline = get_deadline()
    if deadline is None:
        return False
    return dt + timedelta(minutes=timeout_minutes) > deadline

def get_time_to_deadline() -> timedelta:
    deadline = get_deadline()
    if deadline is None:
        return timedelta.max
    return deadline - get_current_normalized_time()

PATCH_YAML_DOWNLOADED_CACHE_DIR = Path("/tmp/patch-yaml-cache")

def get_pd_client():
    if PDClient is None:
        _l.error("PDClient is not installed")
        raise ValueError("PDClient is not installed")

    CRS_TASK_NUM = os.environ.get("CRS_TASK_NUM", os.environ.get("ARTIPHISHELL_GLOBAL_ENV_CRS_TASK_NUM", None))

    agent_url = os.environ.get(f"PYDATATASK_AGENT_{CRS_TASK_NUM}_PORT",
        os.environ.get("PYDATATASK_AGENT_PORT",
        os.environ.get("PDT_AGENT_URL", "")
    ))
    agent_url = agent_url.replace("tcp://", "http://")
    agent_secret = os.environ.get("AGENT_SECRET", os.environ.get("PDT_AGENT_SECRET", ""))

    if not agent_url:
        _l.error(f"PD agent URL is not set in environment variables for CRS_TASK_NUM={CRS_TASK_NUM}")
        raise ValueError(f"PD agent URL is not set in environment variables for CRS_TASK_NUM={CRS_TASK_NUM}")

    return PDClient(agent_url, agent_secret)

def verify_patch_metadata_is_valid(patch_id):
    try:
        PATCH_YAML_DOWNLOADED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        patch_yaml_path = PATCH_YAML_DOWNLOADED_CACHE_DIR / f"{patch_id}.yaml"

        if not patch_yaml_path.exists():
            client = get_pd_client()
            if not client:
                _l.error(f"Unable to get PD client, assuming patch metadata is valid for {patch_id}")
                return True
            tmp_file = Path(str(patch_yaml_path) + ".tmp")
            res = client.get_data(
                'allow_patch_submission',
                'patch_metadata',
                patch_id,
                out_file_path=str(tmp_file),
                allow_missing=True,
            )
            if not res:
                _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, it is missing from the pipeline")
                return False
            if not tmp_file.exists():
                _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, we thought we downloaded it but it's not here!")
                return False
            file_content = tmp_file.read_text()
            if not file_content:
                _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is empty!")
                tmp_file.unlink(missing_ok = True)
                return False
            if file_content.strip() == '{}':
                _l.warning(f"️🐢 Metadata for {patch_id} has not been uploaded yet...")
                tmp_file.unlink(missing_ok = True)
                return False

            # Verify that it is valid yaml before we save it to the cache
            try:
                yaml_data = yaml.safe_load(file_content)
            except Exception as e:
                _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is not valid yaml: {e}", exc_info=True)
                tmp_file.unlink(missing_ok = True)
                return False
            if not yaml_data:
                _l.warning(f"⚠️ Metadata for {patch_id} is empty or null")
                tmp_file.unlink(missing_ok = True)
                return False

            tmp_file.rename(patch_yaml_path)

        if not patch_yaml_path.exists():
            _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is not here!")
            return False

        try:
            patch_yaml_data = yaml.safe_load(patch_yaml_path.read_text())
        except Exception as e:
            _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is not valid yaml: {e}", exc_info=True)
            return False

        if patch_yaml_data is None:
            # We have a literal null in the file, this means that it failed to upload to the pipeline!
            _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is null!")
            return False

        # Verify that the patch metadata is valid
        if not isinstance(patch_yaml_data, dict):
            _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is not a dictionary!")
            return False

        # Try to access the `pdt_project_id` entry in the patch metadata
        # If we cannot access this, then we will never be able to submit this patch (wont launch in the pipeline!)
        try:
            pdt_project_id = patch_yaml_data['pdt_project_id']
            if not pdt_project_id:
                _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the `pdt_project_id` entry is empty!")
                return False
        except KeyError:
            _l.warning(f"⚠️ Unable to get patch metadata for {patch_id}, the file is missing the `pdt_project_id` entry!", exc_info=True)
            return False

        # We were able to access the `pdt_project_id` entry in the patch metadata
        # This means that the patch metadata is valid and we can submit it to the pipeline
        return True

    except Exception as e:
        _l.warning(f"⚠️ Encountered unexpected error while verifying patch metadata for {patch_id}, assuming it is valid: {e}", exc_info=True)
        return True


@dataclass
class ClusterAnalysis:
    """
    This class is used to analyze the patches in a cluster.
    It will find the best patch for each cluster and return it.
    """
    newest_patch: Optional[GeneratedPatch] = None
    oldest_patch: Optional[GeneratedPatch] = None
    newest_dedup_node: Optional[OrganizerDedupInfoNode] = None
    oldest_dedup_node: Optional[OrganizerDedupInfoNode] = None
    newest_pov: Optional[PoVReportNode] = None
    oldest_pov: Optional[PoVReportNode] = None

    perfect_patches: List[GeneratedPatch] = field(default_factory=list)
    most_recent_best_patch: Optional[GeneratedPatch] = None
    most_recent_best_mitigated: int = 0
    oldest_best_patch: Optional[GeneratedPatch] = None
    oldest_best_patch_no_py: Optional[GeneratedPatch] = None
    already_submitted_patches: List[GeneratedPatch] = field(default_factory=list)
    already_submitted_perfect_patches: List[GeneratedPatch] = field(default_factory=list)

    oldest_pov_for_newest_dedup_node: Optional[PoVReportNode] = None
    first_pov_bypassing_oldest_best_patch: Optional[PoVReportNode] = None

@dataclass
class BucketAnalsis:
    initial_patch_request: bool = False
    initial_patch_poi_id: Optional[str] = None

    patch_refine_id: Optional[str] = None
    patch_refine_poi_id: Optional[str] = None

    perfect_patch_bypass_id: Optional[str] = None

# used to trace if we have send a failed functionality refinement request
submitted_patch_tracker: dict[str, dict] = {}
failed_functionality_patches = []


def analyze_cluster(i, cluster: Cluster):
    global submitted_patch_tracker, failed_functionality_patches

    newest_dedup_node = max(cluster.organizer_dedup_info_nodes, key=lambda dedup: dedup.first_discovered, default=None)
    oldest_dedup_node = min(cluster.organizer_dedup_info_nodes, key=lambda dedup: dedup.first_discovered, default=None)
    newest_pov = max(cluster.pov_report_nodes, key=lambda pov: pov.first_discovered, default=None)
    oldest_pov = min(cluster.pov_report_nodes, key=lambda pov: pov.first_discovered, default=None)
    newest_patch = None
    oldest_patch = None

    perfect_patches = []
    most_recent_best_patch, most_recent_best_mitigated = None, 0
    oldest_best_patch = None
    oldest_best_patch_no_py = None
    most_recent_best_mitigated_no_py = 0
    already_submitted_patches = []
    already_submitted_perfect_patches = []

    has_any_patches_with_valid_metadata = False
    valid_metadata_map = {}
    for patch in cluster.generated_patches:
        patch_has_valid_metadata = verify_patch_metadata_is_valid(patch.patch_key)
        valid_metadata_map[patch.patch_key] = patch_has_valid_metadata
        if patch_has_valid_metadata:
            has_any_patches_with_valid_metadata = True
        else:
            _l.warning(f"⚠️ Patch metadata is invalid for {patch.patch_key}")

    # Assume the order here is random (unordered)
    for patch in cluster.generated_patches:
        patch_has_valid_metadata = valid_metadata_map.get(patch.patch_key, True)

        if not patch_has_valid_metadata:
            # If a patch does not have valid metadata, we will unconditionally ignore it
            _l.info(f"{patch.patch_key} has invalid metadata, skipping it")
            continue

        if newest_patch is None or normalize_time(patch.time_created) > normalize_time(newest_patch.time_created):
            newest_patch = patch
        if oldest_patch is None or normalize_time(patch.time_created) < normalize_time(oldest_patch.time_created):
            oldest_patch = patch
        mitigated_in_cluster = patch.mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        ).all()
        unmitigated_in_cluster = patch.non_mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        ).all()

        num_mitigated = len(mitigated_in_cluster)
        num_unmitigated = len(unmitigated_in_cluster)
        num_povs_in_cluster = len(cluster.pov_report_nodes)
        _l.info(f"Cluster {i} patch {patch.patch_key} mitigates {num_mitigated}/{num_povs_in_cluster} POVs, but does not mitigate {num_unmitigated} POVs")

        if patch.submitted_time or patch.imperfect_submission_in_endgame and not patch.fail_functionality:
            already_submitted_patches.append(patch)
            if not patch.imperfect_submission_in_endgame:
                already_submitted_perfect_patches.append(patch)
            # a patch must have a mitigated pov to show in cluster
            if patch.patch_key not in submitted_patch_tracker:
                submitted_patch_tracker[patch.patch_key] = {
                    'poi_report_id': mitigated_in_cluster[0].key if mitigated_in_cluster else None,
                    'functionality_refine_submitted': False,
                }

        if num_mitigated == 0:
            _l.info(f"Found patch for cluster {i} that does not mitigate any POVs: {patch.patch_key}, skipping")
            continue

        # If we mitigated all the povs, mark it as a perfect patch
        if num_mitigated == num_povs_in_cluster:
            _l.info(f"Found perfect patch for cluster {i}: {patch.patch_key}")
            # However, if we cannot verify the patch metadata, we should not consider it as a perfect patch as we can't submit it
            # We should try to find a patch we can submit that is perfect instead
            if not patch_has_valid_metadata:
                _l.warning(f"⚠️ Patch metadata is invalid for {patch.patch_key}, not marking it as perfect")
            else:
                perfect_patches.append(patch)

        # track the most recent best patch for best-effort patching in case of failure

        if num_mitigated > most_recent_best_mitigated:
            _l.info(f"Found better patch for cluster {i}: {patch.patch_key} (mitigated {num_mitigated} POVs vs {most_recent_best_mitigated} from {most_recent_best_patch.patch_key if most_recent_best_patch else 'None'})")

            # If this is the first patch we find with this num
            # We set out base line state to this patch
            oldest_best_patch = patch
            most_recent_best_mitigated = num_mitigated
            most_recent_best_patch = patch

        if patch.patcher_name != "PatcherY":
            if num_mitigated > most_recent_best_mitigated_no_py:
                _l.info(f"Found better patch for cluster {i} (non-Patchery): {patch.patch_key} (mitigated {num_mitigated} POVs vs {most_recent_best_mitigated_no_py} from {most_recent_best_patch.patch_key if most_recent_best_patch else 'None'})")
                # If this is the first patch we find with this num
                # We set out base line state to this patch
                oldest_best_patch_no_py = patch
                most_recent_best_mitigated_no_py = num_mitigated
            elif num_mitigated == most_recent_best_mitigated_no_py:
                _l.info(
                    f"Found older equally-good non-Patchery patch for cluster {i}: "
                    f"{patch.patch_key}"
                )
                if normalize_time(patch.time_created) < normalize_time(oldest_best_patch_no_py.time_created):
                    oldest_best_patch_no_py = patch

        # For patches in this same level of mitigation:
        if num_mitigated == most_recent_best_mitigated:
            # If this patch is newer
            if normalize_time(patch.time_created) > normalize_time(most_recent_best_patch.time_created):
                _l.info(f"Found newer patch for cluster {i}: {patch.patch_key} (mitigated {num_mitigated} POVs vs {most_recent_best_mitigated} from {most_recent_best_patch.patch_key if most_recent_best_patch else 'None'})")
                # We update that this is a newer patch
                most_recent_best_patch = patch
            if normalize_time(patch.time_created) < normalize_time(oldest_best_patch.time_created):
                _l.info(f"Found older patch for cluster {i}: {patch.patch_key} (mitigated {num_mitigated} POVs vs {most_recent_best_mitigated} from {most_recent_best_patch.patch_key if most_recent_best_patch else 'None'})")
                # We update that this is the oldest patch
                oldest_best_patch = patch

    # Secondary perfection condition: If the oldest best non-all-mitigating patch does not have ANY unmitigated crashes, we also
    # consider it perfect. The main case of this would be the xmlStrndup where we keep finding more and more PoVs that slowly trickle in.
    if oldest_best_patch:
        oldest_best_patch_num_unmitigated_in_cluster = len(oldest_best_patch.non_mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        ))
        # in the beginning of the game, patch patrol may be hanging so we need to make sure the patch is processed
        # otherwise the num_unmitigated_in_cluster is always 0
        if oldest_best_patch_num_unmitigated_in_cluster == 0 and (len(oldest_best_patch.non_mitigated_povs) > 0 or oldest_best_patch.finished_patch_patrol):
            _l.info(f"Oldest best patch for cluster {i} is perfect: {oldest_best_patch.patch_key} (mitigated {most_recent_best_mitigated} POVs)")
            patch_has_valid_metadata = valid_metadata_map.get(oldest_best_patch.patch_key, True)
            if not patch_has_valid_metadata:
                _l.warning(f"⚠️ Patch metadata is invalid for {oldest_best_patch.patch_key}, not marking it as perfect")
            else:
                perfect_patches.append(oldest_best_patch)

    oldest_pov_for_newest_dedup_node = None
    first_pov_bypassing_oldest_best_patch = None

    # find the oldest PoV for the newest DedupNode
    for pov_node in cluster.pov_report_nodes:
        if newest_dedup_node and pov_node.organizer_dedup_infos.is_connected(newest_dedup_node) and \
            (oldest_pov_for_newest_dedup_node is None or pov_node.first_discovered < oldest_pov_for_newest_dedup_node.first_discovered):
            oldest_pov_for_newest_dedup_node = pov_node

        if oldest_best_patch:
            # find the first PoV that bypasses the oldest best patch
            if oldest_best_patch.non_mitigated_povs.is_connected(pov_node):
                if first_pov_bypassing_oldest_best_patch is None or pov_node.first_discovered < first_pov_bypassing_oldest_best_patch.first_discovered:
                    first_pov_bypassing_oldest_best_patch = pov_node

    # pov analysis
    return ClusterAnalysis(
        perfect_patches=perfect_patches,
        most_recent_best_patch=most_recent_best_patch,
        most_recent_best_mitigated=most_recent_best_mitigated,
        oldest_best_patch=oldest_best_patch,
        oldest_best_patch_no_py=oldest_best_patch_no_py,
        already_submitted_patches=already_submitted_patches,
        already_submitted_perfect_patches=already_submitted_perfect_patches,
        newest_dedup_node=newest_dedup_node,
        oldest_dedup_node=oldest_dedup_node,
        newest_pov=newest_pov,
        oldest_pov=oldest_pov,
        newest_patch=newest_patch,
        oldest_patch=oldest_patch,
        oldest_pov_for_newest_dedup_node=oldest_pov_for_newest_dedup_node,
        first_pov_bypassing_oldest_best_patch=first_pov_bypassing_oldest_best_patch,
    )

def select_patches_to_submit(cluster_and_analysis_pairs: List[Tuple[Cluster, ClusterAnalysis]]) -> Iterator[tuple[GeneratedPatch, bool, Cluster]]:
    for i, (cluster, analysis) in enumerate(cluster_and_analysis_pairs):
        try:
            _l.info(f"Analyzing cluster {i}:")
            _l.info(f'    {len(cluster.pov_report_nodes)} PoVs: ' + ', '.join([str(pov.key) for pov in cluster.pov_report_nodes]))
            _l.info(f'    {len(cluster.organizer_dedup_info_nodes)} OrganizerDedupInfoNodes: ' + ', '.join([str(dedup.identifier) for dedup in cluster.organizer_dedup_info_nodes]))
            _l.info(f'    {len(cluster.generated_patches)} GeneratedPatches: ' + ', '.join([str(patch.patch_key) for patch in cluster.generated_patches]))


            _l.info(f"Cluster {i} has {len(analysis.already_submitted_patches)} already submitted patches: " + ', '.join([str(patch.patch_key) for patch in analysis.already_submitted_patches]))

            # if a perfect patch exists that is at least 5 minutes old, submit it
            # If there are ANY perfect patches, that means that the "oldest_best_patch" is a perfect patch
            # We'll just check the oldest patch as as it is most likely to already be 5 min old
            # "oldest_best_patch" will be the oldest patch with the highest level of mitigation
            # meaning "oldest_best_patch" is the oldest perfect patch

            is_imperfect = False
            time_to_deadline = get_time_to_deadline()
            in_endgame = time_to_deadline < timedelta(minutes=NON_PERFECT_PATCH_SUBMISSION_TIMEOUT_MINUTES)
            # It is also important that we only submit the OLDEST patch
            # This is so that we only submit one best patch per cluster
            if analysis.already_submitted_patches and len(analysis.already_submitted_patches) > TOO_MANY_PATCHES_PER_BUCKETS:
                good_patch_submission_timeout_minutes_per_bucket = GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES * 2
            else:
                good_patch_submission_timeout_minutes_per_bucket = GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES
            if analysis.perfect_patches and analysis.oldest_best_patch:
                if is_patch_older_than_minutes(analysis.oldest_best_patch, good_patch_submission_timeout_minutes_per_bucket):
                    if analysis.oldest_best_patch.patcher_name == "PatcherY":
                        # if the only perfect patch is patchery dump, skip it for now
                        # if at the end of the game we still have only one perfect patch, we will submit it
                        if all([patch.patcher_name == "PatcherY" for patch in analysis.perfect_patches]):
                            if not in_endgame:
                                continue
                        # if we have more than one perfect patch, we will check if the best_patch besides Patchery is perfect
                        else:
                            oldest_best_patch_no_patchery = analysis.oldest_best_patch_no_py
                            patch_ids = [patch.patch_key for patch in analysis.perfect_patches]
                            if oldest_best_patch_no_patchery and oldest_best_patch_no_patchery.patch_key in patch_ids:
                                if is_patch_older_than_minutes(oldest_best_patch_no_patchery, good_patch_submission_timeout_minutes_per_bucket):
                                    _l.info(
                                        f"Submitting the second oldest perfect patch besides Patchery dump for cluster {i}: {oldest_best_patch_no_patchery.patch_key} as it is {get_patch_age(oldest_best_patch_no_patchery)} old")
                                    yield oldest_best_patch_no_patchery, is_imperfect, cluster
                            # in case the oldest_patch_no_patchery is not in the perfect patches, we will find the second oldest perfect patch that is not from Patchery
                            else:
                                _l.info(f"Best patch besides patchery {oldest_best_patch_no_patchery.patch_key} not in perfect patches {patch_ids} which is wrong")
                                oldest_best_patch_no_patchery = None
                                for p in analysis.perfect_patches:
                                    if p.patcher_name != "PatcherY":
                                        if oldest_best_patch_no_patchery is None:
                                            oldest_best_patch_no_patchery = p
                                        else:
                                            if normalize_time(p.time_created) < normalize_time(oldest_best_patch_no_patchery.time_created):
                                                oldest_best_patch_no_patchery = p
                                if oldest_best_patch_no_patchery and is_patch_older_than_minutes(oldest_best_patch_no_patchery, good_patch_submission_timeout_minutes_per_bucket):
                                    _l.info(f"Submitting the second oldest perfect patch for cluster {i}: {oldest_best_patch_no_patchery.patch_key} as it is {get_patch_age(oldest_best_patch_no_patchery)} old")
                                    yield oldest_best_patch_no_patchery, is_imperfect, cluster
                            continue
                    _l.info(f"Submitting perfect patch for cluster {i}: {analysis.oldest_best_patch.patch_key} as it is {get_patch_age(analysis.oldest_best_patch)} old")
                    yield analysis.oldest_best_patch, is_imperfect, cluster
                elif in_endgame:
                    is_imperfect = True
                    analysis.oldest_best_patch.imperfect_submission_in_endgame = True
                    analysis.oldest_best_patch.save()
                    yield analysis.oldest_best_patch, is_imperfect, cluster
                else:
                    _l.info(f"NOT submitting perfect patch for cluster {i}: {analysis.oldest_best_patch.patch_key} as it is {get_patch_age(analysis.oldest_best_patch)} old")

            # Otherwise, we have no perfect patch...
            # But we may have a pretty good patch that fixes some bugs
            # In this case, we wait until the end of the game to submit to have the best chance of scoring with it.
            elif analysis.most_recent_best_patch and analysis.most_recent_best_mitigated > 0:
                assert analysis.oldest_best_patch is not None, f"If we have a most recent best patch, we should also have an oldest best patch. Despite this, we have {analysis.oldest_best_patch=} and {analysis.most_recent_best_patch=}"

                # we haven't submitted any patches for this cluster yet
                # it's near the end of the game and we haven't found a better one.
                time_to_submission = time_to_deadline - timedelta(minutes=NON_PERFECT_PATCH_SUBMISSION_TIMEOUT_MINUTES)
                is_imperfect = True

                # we should always bail early if we already submitted a patch for this cluster that is imperfect
                if analysis.oldest_best_patch.imperfect_submission_in_endgame:
                    yield analysis.oldest_best_patch, is_imperfect, cluster
                elif analysis.oldest_best_patch_no_py and analysis.oldest_best_patch_no_py.imperfect_submission_in_endgame:
                    yield analysis.oldest_best_patch_no_py, is_imperfect, cluster
                # XXX: analysis.already_submitted_patches is based on the patch's submitted_time, which is updated by the
                # submitter. There is a race condition here! What if the submitter has not updated the submitted_time yet, but
                # we are on our second loop of this already. We could end up submitting ANOTHER imperfect patch which changed in the
                # loop wait.
                elif in_endgame and len(analysis.already_submitted_patches) == 0:
                    # if the oldest best patch is from Patchery, we check if we have a non-Patchery patch that mitigates the same number, if so submit that one
                    no_py_num_mitigated = 0
                    if analysis.oldest_best_patch.patcher_name == "PatcherY":
                        if analysis.oldest_best_patch_no_py is not None:
                            no_py_num_mitigated = len(
                                analysis.oldest_best_patch_no_py.mitigated_povs.filter(
                                    key__in=[pov.key for pov in cluster.pov_report_nodes]
                                ))
                        if no_py_num_mitigated == analysis.most_recent_best_mitigated:
                            _l.info(f"NO TIME LEFT! The oldest best patch is from PatcherY, but we have a non-Patchery patch that mitigates the same number of PoVs ({no_py_num_mitigated}) as the most recent best patch ({analysis.most_recent_best_mitigated}). Submitting {i}: {analysis.oldest_best_patch_no_py.patch_key}")
                            analysis.oldest_best_patch_no_py.imperfect_submission_in_endgame = True
                            analysis.oldest_best_patch_no_py.save()
                            yield analysis.oldest_best_patch_no_py, is_imperfect, cluster
                            continue
                    _l.info(f"NO TIME LEFT! NOW OR NEVER! Submitting {i}: {analysis.oldest_best_patch.patch_key}")
                    analysis.oldest_best_patch.imperfect_submission_in_endgame = True
                    analysis.oldest_best_patch.save()
                    yield analysis.oldest_best_patch, is_imperfect, cluster
                else:
                    if len(analysis.already_submitted_patches) > 0:
                        _l.info(f"NOT submitting {i}: {analysis.oldest_best_patch.patch_key}. It is imperfect and will NOT be submitted in {time_to_submission}, since we have already submitted.")
                        for p in sorted(analysis.already_submitted_patches, key=lambda p: p.time_created, reverse=True):
                            _l.info(f"\tAlready submitted patch for cluster {i}: {p.patch_key}, {p.submitted_time=} {p.time_created=}")
                    else:
                        _l.info(f"NOT submitting {i}: {analysis.oldest_best_patch.patch_key}. It is imperfect but will be submitted in {time_to_submission} if no better patch is found.")

            else:
                # if we have no perfect patch and no good patch, we have no patches.
                pass
        except Exception as e:
            _l.error(f"Error analyzing cluster {i}", exc_info=True)
            continue


def select_harness_inputs_to_submit(clusters_and_analysis_pairs: List[Tuple[Cluster, ClusterAnalysis]]) -> Iterator[HarnessInputNode]:
    for i, (cluster, cluster_analysis) in enumerate(clusters_and_analysis_pairs):
        try:

            ################### ENDGAME STRATEGY: setup to decide if we need to submit any (aka all) harness inputs #######################
            # find if there is an endgame imperfect patch that was submitted
            # and if so, check if we have previously already submitted a PoV in the same cluster that is mitigated by that imperfect patch
            # in that case, we don't need to submit any furhter harness inputs to be able to bundle the imperfect patch
            imperfect_patch_was_submitted = False
            pov_for_imperfect_patch_was_already_submitted = False

            for patch in cluster_analysis.already_submitted_patches:
                if not patch.imperfect_submission_in_endgame:
                    continue
                imperfect_patch_was_submitted = True
                _l.info(f"Cluster {i} has an imperfect patch that was submitted: {patch.patch_key}")
                for pov in cluster.pov_report_nodes:
                    if pov.submitted_time and not pov.failed and patch.mitigated_povs.is_connected(pov):
                        _l.info(f"=> the imperfect patch already has a pov submitted for it: {pov.key}, no need to submit again")
                        pov_for_imperfect_patch_was_already_submitted = True
                        break
            ################################################################################################################################

            # Always yield the oldest harness input for the oldest PoV in the cluster
            oldest_pov = cluster_analysis.oldest_pov
            oldest_harness_input = min(oldest_pov.harness_inputs, key=lambda h: h.first_discovered_timestamp)
            yield oldest_harness_input
            _l.info(f"Always yield the oldest harness input for the oldest PoV in the cluster {i}: harness input {oldest_harness_input.identifier} from POV {oldest_pov.key}")

            # now, iterate through all povs and its oldest harness inputs and yield the ones that should be submitted
            oldest_pov_discovered_ts = normalize_time(cluster_analysis.oldest_pov.first_discovered).timestamp()
            for pov in cluster.pov_report_nodes:
                if not pov.harness_inputs:
                    _l.info(f"Cluster {i} has PoV {pov.key} with no harness inputs, skipping")
                    continue
                oldest_harness_input = min(pov.harness_inputs, key=lambda h: h.first_discovered_timestamp)
                now = get_current_normalized_time().timestamp()
                current_age_difference = now - oldest_pov_discovered_ts
                if current_age_difference < NEW_BUCKET_HARNESS_INPUT_SUBMISSION_CUTOFF_MINUTES * 60:
                    # we submit the harness input since it is from within the first 15 minutes of the Bucket's creation
                    _l.info(f"Cluster {i} has PoV {pov.key} that is less than {NEW_BUCKET_HARNESS_INPUT_SUBMISSION_CUTOFF_MINUTES} minutes older than the oldest PoV in the cluster, submitting harness inputs")
                    yield oldest_harness_input
                elif len(cluster_analysis.already_submitted_perfect_patches) > 1:
                    # we also submit if there is multiple submitted perfect patches and the harness input is older
                    # than the creation of the newest submitted perfect patch
                    harness_input_discovered_ts = normalize_time(oldest_harness_input.first_discovered_timestamp).timestamp()
                    newest_submitted_patch = max(cluster_analysis.already_submitted_perfect_patches, key=lambda p: normalize_time(p.submitted_time).timestamp(), default=None)
                    newest_submitted_patch_created_ts = normalize_time(newest_submitted_patch.time_created).timestamp()
                    harness_input_found_before_newest_submitted_patch_creation = harness_input_discovered_ts < newest_submitted_patch_created_ts
                    if harness_input_found_before_newest_submitted_patch_creation: # we have a submitted k
                        # since we have multiple perfect patches, and one has to have been bypassed, so we submit one harness input
                        # to break other team's patches as well since we have a perfect patch against the cluster and don't hurt ourselves
                        yield oldest_harness_input

                # last step: if a pov was submitted where the imperfect patch already mitigates it, then we don't
                # have to submit anything
                if imperfect_patch_was_submitted and not pov_for_imperfect_patch_was_already_submitted:
                    # submit
                    yield oldest_harness_input

        except Exception as e:
            _l.error(f"Error analyzing cluster {i} for harness inputs", exc_info=True)
            continue

def write_patch_submission_edict(patch: GeneratedPatch, patch_submission_path: Path):
    patch_key = patch.patch_key
    with open(patch_submission_path / str(patch_key), 'w') as f:
        json.dump({
            'patcher_name': patch.patcher_name,
            'total_cost': patch.total_cost,
            'poi_report_id': list(patch.pov_report_generated_from)[0].key,
        }, f, indent=2)

def write_crash_submission_edict(harness_input: HarnessInputNode, crashing_input_submission_path: Path):
    crash_key = hashlib.md5(bytes.fromhex(str(harness_input.content_hex))).hexdigest()
    _l.info("Writing crash submission edict for crash key: %s", crash_key)
    with open(crashing_input_submission_path / crash_key, 'wb') as f:
        f.write(b"{}")

def write_patch_request(request_type: str, poi_report_id: str, bucket_id: str | None, patch_request_meta: Path,
                        patch_id: str | None = None, patcher_name: str | None = None, failed_functionality: bool = False):
    request = PatchRequestMeta(
        request_type=request_type,
        poi_report_id=poi_report_id,
        patch_id=patch_id,
        patcher_name=patcher_name,
        bucket_id=bucket_id,
        failed_functionality=failed_functionality,
    )
    request_dict = request.model_dump()
    _l.info(f"Writing patch request {request_type} to {patch_request_meta}")
    with open(patch_request_meta, 'w') as f:
        yaml.safe_dump(request_dict, f, default_flow_style=False, sort_keys=False)


def write_bypass_request(project_id: str, harness_id: str, patch_id: str,
                         mitigated_poi_report_id: str, patcher_name: str, build_request_id: str,
                         patch_bypass_request_meta: Path,
                         patch_description: str | None = None, sanitizer_name: str | None = None):
    request = PatchBypassRequestMeta(
        project_id=project_id, harness_id=harness_id, patch_id=patch_id,
        mitigated_poi_report_id=mitigated_poi_report_id, patcher_name=patcher_name, build_request_id=build_request_id,
        patch_description=patch_description, sanitizer_name=sanitizer_name
    )
    request_dict = request.model_dump()
    _l.info(f"Writing patch bypass request to {patch_bypass_request_meta}")
    with open(patch_bypass_request_meta, 'w') as f:
        yaml.safe_dump(request_dict, f, default_flow_style=False, sort_keys=False)


def update_or_create_bucket(project_id: str, bucket_key: str, cluster_map:  dict[str, Cluster]):
    """
    Update or create a bucket in the analysis graph.
    If the bucket already exists, it will be updated with the new information.
    If it does not exist, it will be created.
    """
    cluster = cluster_map.get(bucket_key, None)
    if cluster is None:
        _l.info(f"{bucket_key} not found in cluster map, skipping bucket update/creation.")
        return

    max_povs = 0
    all_relevant_patches = []
    contains_povs = [pov.key for pov in cluster.pov_report_nodes]
    best_patch_id = None
    oldest_patch_time = None
    patch_mitigated_povs: dict[str, int] = generate_patch_povs_map(cluster)

    for patch in cluster.generated_patches:
        mitigated_in_cluster = patch_mitigated_povs[patch.patch_key]
        if mitigated_in_cluster > max_povs:
            max_povs = mitigated_in_cluster
        all_relevant_patches.append(patch.patch_key)
    for patch in cluster.generated_patches:
        if patch_mitigated_povs[patch.patch_key] == max_povs:
            if oldest_patch_time is None:
                oldest_patch_time = patch.time_created
                best_patch_id = patch.patch_key
            else:
                if normalize_time(patch.time_created) < normalize_time(oldest_patch_time):
                    best_patch_id = patch.patch_key
    _l.info(f"Bucket {bucket_key} best patch: {best_patch_id} with {max_povs} / {len(contains_povs)} mitigated PoVs.")
    _l.info(f"Updating existing bucket {bucket_key}")
    BucketNode.upload_bucket(project_id, bucket_key, datetime.now(), best_patch_id, contains_povs,
                             all_relevant_patches)
    return


def process_bucket(project_id: str, bucket_key: str, cluster_map: dict[str, Cluster], patch_request_meta_path: Path, bucket_analysis: dict[str, BucketAnalsis], patch_bypass_requests: Path ):
    # for each cluster
    # if any poi report is not mitigated by all the patches in its cluster
    # - if a patch is available, issue refine patch request (patch request with the patch id)
    # - if no patch is available, issue a new patch request
    # if a cluster has not been patched for a while(last updated for more than 30 mins), issue a new patch request
    # if a cluster contains submitter retry, issue a refine patch request

    all_relevant_povs = []
    all_mitigated_pov_ids = []
    all_relevant_pov_map = {}
    cluster = cluster_map.get(bucket_key, None)
    bucket_state = bucket_analysis.get(bucket_key, None)
    if cluster is None:
        _l.info(f"Bucket {bucket_key} not found.")
        return
    if bucket_state is None:
        _l.warning(f"Bucket {bucket_key} not found in Bucket Analysis. Some thing is really wrong, please check the code.")
        return
    # Get all POVs from the cluster
    for pov_node in cluster.pov_report_nodes:
        all_relevant_povs.append(pov_node.key)
        all_relevant_pov_map[pov_node.key] = pov_node

    # If the cluster has no patches, issue a new patch request
    if len(cluster.generated_patches) == 0:
        if all_relevant_povs:  # Check to prevent IndexError
            latest_discovered_pov = max(cluster.pov_report_nodes, key=lambda pov: pov.first_discovered)
            # if no patch request has been issued yet, issue a new patch request or new pov came in issue a new patch request
            if (bucket_state.initial_patch_request is False and bucket_state.initial_patch_poi_id is None)\
                or bucket_state.initial_patch_poi_id != latest_discovered_pov.key:
                file_name = hashlib.md5(f"patch_{latest_discovered_pov.key}".encode(errors="ignore")).hexdigest()
                _l.info("No patches found for bucket %s, issuing new patch request for POV %s", bucket_key,
                        latest_discovered_pov.key)
                write_patch_request('patch', poi_report_id=latest_discovered_pov.key, bucket_id=bucket_key,
                                    patch_request_meta=patch_request_meta_path / file_name)
                bucket_state.initial_patch_request = True
                bucket_state.initial_patch_poi_id = latest_discovered_pov.key
        return

    # Process all patches to find the best one
    patcher_name = None
    perfect_patch_id = None
    patch_mitigated_povs = generate_patch_povs_map(cluster)
    _l.info(f"Current Bucket patches mitigated PoVs: {patch_mitigated_povs}")
    # First check if the bucket's best patch is perfect
    best_bucket_patch = None
    is_best_patch_perfect = False
    best_patch_key = None

    # Find the bucket's best patch
    for bucket in BucketNode.nodes.filter(bucket_key=bucket_key, pdt_project_id=project_id):
        if bucket.best_patch_key:
            best_patch_key = bucket.best_patch_key
            best_bucket_patch = next((p for p in cluster.generated_patches if p.patch_key == best_patch_key), None)
            break

    # Check if best patch is perfect (mitigates all POVs)
    if best_bucket_patch and best_patch_key in patch_mitigated_povs:
        if patch_mitigated_povs[best_patch_key] == len(cluster.pov_report_nodes):
            is_best_patch_perfect = True

    # Process patches - either use the best bucket patch if perfect, or find one perfect patch
    patch_to_bypass = None

    if is_best_patch_perfect and best_bucket_patch:
        # Use the bucket's best patch since it's perfect
        patch_to_bypass = best_bucket_patch
        _l.info(f"Using bucket's best patch {best_bucket_patch.patch_key} for bypass as it's perfect")
    else:
        # Find one perfect patch
        for patch_key, mitigated_povs_in_cluster in patch_mitigated_povs.items():
            # Skip if not a perfect patch
            if mitigated_povs_in_cluster < len(cluster.pov_report_nodes):
                continue

            patch = next((p for p in cluster.generated_patches if p.patch_key == patch_key), None)
            if patch is None:
                _l.info(f"Patch {patch_key} not found in cluster.")
                continue

            _l.info(f"Found perfect patch {patch.patch_key} for bucket {bucket_key}")
            patch_to_bypass = patch
            break  # Only need one perfect patch

    # Issue bypass request if we found a patch to bypass
    if patch_to_bypass:
        # Get harness input information
        if not cluster.pov_report_nodes:
            return
        first_pov = cluster.pov_report_nodes[0]
        harness_inputs = first_pov.harness_inputs.all()
        harness_input = harness_inputs[0] if harness_inputs else None
        if harness_input is None:
            return

        # Issue bypass request if needed
        build_request_id = patch_to_bypass.extra_metadata.get('build_request_id', None)
        if build_request_id and (bucket_state.perfect_patch_bypass_id is None or
                                 bucket_state.perfect_patch_bypass_id != patch_to_bypass.patch_key):
            bucket_state.perfect_patch_bypass_id = patch_to_bypass.patch_key
            perfect_patch_id = patch_to_bypass.patch_key
            _l.info(
                f"Issuing patch bypass request for perfect patch {patch_to_bypass.patch_key} for bucket {bucket_key}")
            file_name = hashlib.md5(f"bypass_{patch_to_bypass.patch_key}".encode(errors="ignore")).hexdigest()
            write_bypass_request(
                project_id=harness_input.pdt_project_id,
                harness_id=harness_input.pdt_harness_info_id,
                patch_id=patch_to_bypass.patch_key,
                mitigated_poi_report_id=first_pov.key,
                patcher_name=patch_to_bypass.patcher_name,
                build_request_id=build_request_id,
                patch_bypass_request_meta=patch_bypass_requests / file_name,
                patch_description=patch_to_bypass.extra_metadata.get('summary', None)
            )

    if not perfect_patch_id:
        # if there is no perfect patch, we need to issue refine patch requests
        best_patch = None
        best_patch_id = None
        non_mitigated_pov_nodes = []
        # Find the patch that mitigates the most POVs
        best_patch_key, max_povs = max(patch_mitigated_povs.items(), key=lambda x: x[1], default=(None, 0))
        if best_patch_key is not None:
            best_patch = next((p for p in cluster.generated_patches if p.patch_key == best_patch_key), None)
        if best_patch is not None:
            best_patch_id = best_patch.patch_key
            patcher_name = best_patch.patcher_name
            # Find all non-mitigated POVs for the best patch
            non_mitigated_pov_nodes = best_patch.non_mitigated_povs.filter(
                key__in=[pov.key for pov in cluster.pov_report_nodes]
            ).all()
        # Issue refine patch request if needed
        if non_mitigated_pov_nodes:
            if bucket_state.patch_refine_id is None or best_patch_id != bucket_state.patch_refine_id:
                latest_discovered_unmitigated_pov = max(non_mitigated_pov_nodes, key=lambda pov: pov.first_discovered)
                bucket_state.patch_refine_id = best_patch_id
                bucket_state.patch_refine_poi_id = latest_discovered_unmitigated_pov.key
                _l.info(f"Found non-mitigated POVs for bucket {bucket_key}, issuing refine patch request for POV {latest_discovered_unmitigated_pov.key}")
                file_name = hashlib.md5(f"refine_{best_patch_id}".encode(errors="ignore")).hexdigest()
                write_patch_request('refine', poi_report_id=latest_discovered_unmitigated_pov.key, bucket_id=bucket_key,
                                    patch_request_meta=patch_request_meta_path / file_name, patch_id=best_patch_id, patcher_name=patcher_name)
                return

    return


def generate_patch_povs_map(cluster: Cluster):
    patch_mitigated_povs: dict[str, int] = {}
    # We will store the mitigated PoVs for each patch
    for patch in cluster.generated_patches:
        mitigated_in_cluster = patch.mitigated_povs.filter(
            key__in=[pov.key for pov in cluster.pov_report_nodes]
        )
        patch_mitigated_povs[patch.patch_key] = len(mitigated_in_cluster)
    return patch_mitigated_povs

def run(
    project_id: str, patch_request_meta_path: Path, patch_bypass_requests: Path, patch_submission_edict_path,
    crash_submission_edict_path: Path, task_type: str
):
    global GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES
    adjust_task_type_globals(task_type)

    """
    Infinite loop to keep querying the analysis graph
    """
    start_time = datetime.now()
    _l.info(f"Starting emperor at {start_time}")
    bucket_analysis = {}
    while True:
        # run for every 30 seconds
        time.sleep(0.1)
        elapsed_seconds = (datetime.now() - start_time).total_seconds()
        _l.info(f"Start Querying the analysis graph at {datetime.now()}")
        _l.info("Time elapsed since last run: %s min", int(elapsed_seconds / 60))
        cluster_bucket_ids = []
        cluster_map = {}

        with logging_timed_context("Finding clusters"):
            clusters = find_clusters(project_id=project_id)
            _l.info(f"Found {len(clusters)} clusters.")

        # adjust the slowdown based on the number of clusters
        new_good_wait_time = update_good_patch_submission_timeout(len(clusters))
        if new_good_wait_time != GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES:
            _l.info("Adjusting the good patch submission timeout from %d to %d minutes", GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES, new_good_wait_time)
            GOOD_PATCH_SUBMISSION_TIMEOUT_MINUTES = new_good_wait_time

        # first iterate over the cluster
        # get all the buckets and save all the buckets that are the same and remove the rest and add new ones
        # if a new cluster is found (new one or merged one) add it to the graph
        for cluster in clusters:
            # bucket key is the hash of sorted dedup_info_nodes identifiers
            try:
                bucket_key = hashlib.md5("".join(
                    sorted([dedup.identifier for dedup in cluster.organizer_dedup_info_nodes])).encode()).hexdigest()
                cluster_bucket_ids.append(bucket_key)
                cluster_map[bucket_key] = cluster
            except Exception as e:
                _l.error("Error while generating bucket key for cluster", exc_info=True)
                continue
        bucket_ids = [bucket.bucket_key for bucket in BucketNode.nodes.filter(pdt_project_id=project_id).all()]

        invalid_buckets = set(bucket_ids) - set(cluster_bucket_ids)
        new_buckets = set(cluster_bucket_ids) - set(bucket_ids)
        with logging_timed_context("Deleting expired buckets"):
            for invalid_bucket in invalid_buckets:
                try:
                    _l.info(f"Invalid bucket found: {invalid_bucket}. This should not happen, please check the graph.")
                    expired_nodes = BucketNode.nodes.filter(bucket_key=invalid_bucket, pdt_project_id=project_id).all()
                    for expired_node in expired_nodes:
                        expired_node.delete()
                    if invalid_bucket in bucket_analysis:
                        del bucket_analysis[invalid_bucket]
                except Exception as e:
                    _l.error("Error while deleting bucket analysis for bucket: %s", invalid_bucket, exc_info=True)
                    continue
        with logging_timed_context("Adding new buckets"):
            for new_bucket in new_buckets:
                try:
                    bucket_analysis[new_bucket] = BucketAnalsis(
                        initial_patch_request=False,
                        initial_patch_poi_id=None,  # This will be set later when we find the first PoV
                        patch_refine_id=None,
                        patch_refine_poi_id=None,
                        perfect_patch_bypass_id=None
                    )
                except Exception as e:
                    _l.error("Error while adding new bucket analysis for bucket %s", new_bucket,  exc_info=True)
                    continue

        # ##DEBUG, only use in local backup run
        # for bucket in cluster_bucket_ids:
        #     bucket_analysis[bucket] = BucketAnalsis(
        #         initial_patch_request=False,
        #         initial_patch_poi_id=None,  # This will be set later when we find the first PoV
        #         patch_refine_id=None,
        #         patch_refine_poi_id=None,
        #         perfect_patch_bypass_id=None
        #     )
        # ##DEBUG, only use in local backup run

        # Process new buckets
        with logging_timed_context("Processing all the buckets"):
            for bucket in cluster_bucket_ids:
                try:
                    update_or_create_bucket(project_id, bucket, cluster_map)
                    process_bucket(project_id, bucket, cluster_map, patch_request_meta_path, bucket_analysis, patch_bypass_requests)
                except Exception as e:
                    _l.error("Error while processing bucket %s", bucket, exc_info=True)
                    continue

        # Perfect patch can fail functionality, so we need to check for that
        with logging_timed_context("Checking for functionality failures in patches"):
            for patch in GeneratedPatch.nodes.filter(pdt_project_id=project_id).all():
                # Check for functionality failures
                try:
                    if patch.patch_key in failed_functionality_patches:
                        continue
                    if patch.fail_functionality:
                        if patch.patch_key in submitted_patch_tracker:
                            bucket_id = None
                            patch_status = submitted_patch_tracker[patch.patch_key]
                            poi_report_id = patch_status['poi_report_id']
                            request_submmited = patch_status['functionality_refine_submitted']
                            if not request_submmited and poi_report_id is not None:
                                for candidate_bucket, cluster in cluster_map.items():
                                    if poi_report_id in [pov.key for pov in cluster.pov_report_nodes]:
                                        bucket_id = candidate_bucket
                                        break
                                # bail out if we can't find the bucket id
                                if bucket_id is None:
                                    continue
                                _l.info(
                                    f"Found functionality failure in patch {patch.patch_key}  issuing refine patch request for POI {poi_report_id}")
                                patch_request_meta_path.mkdir(parents=True, exist_ok=True)
                                file_name = hashlib.md5(f"function_{patch.patch_key}".encode(errors="ignore")).hexdigest()
                                write_patch_request('refine', poi_report_id=poi_report_id,
                                                    bucket_id=bucket_id,
                                                    patch_request_meta=patch_request_meta_path / file_name,
                                                    patch_id=str(patch.patch_key),
                                                    patcher_name=str(patch.patcher_name), failed_functionality=True)
                                failed_functionality_patches.append(patch.patch_key)
                                patch_status['functionality_refine_submitted'] = True
                                continue
                except Exception as e:
                    _l.error("Error while checking patch %s for functionality failures", patch.patch_key, exc_info=True)
                    continue
        with logging_timed_context("Analyzing clusters"):
            clusters_and_analysis_pairs = [
                (cluster, analyze_cluster(i, cluster)) for i, cluster in enumerate(find_clusters(project_id=project_id))
            ]
        # Check for submittable patches and crashing inputs
        _l.info("Checking for submittable patches and crashing inputs")
        with logging_timed_context("Selecting patches to submit"):
            patches = {}
            imperfect_patches = {}
            patch_key_to_score = {}
            for patch, is_imperfect, patch_cluster in select_patches_to_submit(clusters_and_analysis_pairs):
                patch_key_to_score[patch.patch_key] = score_patch(patch, patch_cluster)
                if is_imperfect:
                    # this dictionary will contain the best imperfect patches for each cluster, including those
                    # that we have already submitted in end-game
                    imperfect_patches[patch.patch_key] = patch
                else:
                    patches[patch.patch_key] = patch
        _l.info(f"Found {len(patches)} patches to submit")
        _l.info("Patch scores: %s", patch_key_to_score)
        if len(imperfect_patches) > 0:
            _l.info("Found %d imperfect patches that will be submitted", len(imperfect_patches))

        # Select crashing inputs to submit
        with logging_timed_context("Selecting crashing inputs to submit"):
            # Select crashing inputs to submit
            harness_inputs = {harness_input.content_hash: harness_input for harness_input in
                              select_harness_inputs_to_submit(clusters_and_analysis_pairs)}
        _l.info(f"Found {len(harness_inputs)} crashing inputs to submit")

        patches_to_submit = list(patches.values())
        all_submissions_node: list[PatchergSubmissionNode] = PatchergSubmissionNode.nodes.filter(pdt_project_id=project_id).all()
        submissions_node : PatchergSubmissionNode | None = None
        if len(all_submissions_node) > 1:
            _l.error("Found more than one submission node")
        elif len(all_submissions_node) == 1:
            submissions_node = all_submissions_node[0]
            # create or update the submission node
        elif len(all_submissions_node) == 0:
            PatchergSubmissionNode.upload_node(pdt_project_id=project_id, submitted_imperfect_patches=[])

        # only do imperfect submission in the event that we have started recording imperfect patches
        if submissions_node is not None:
            submitted_imperfect_ids = list(submissions_node.submitted_imperfect_patches)
            if len(imperfect_patches) > 0 and len(submitted_imperfect_ids) < MAX_IMPERFECT_PATCHES_TOTAL:
                # sort imperfect patches by score, then by time created, higher score should be first in list
                sorted_imperfect_patches = sorted(imperfect_patches.values(), key=lambda p: (patch_key_to_score[p.patch_key], -normalize_time(p.time_created).timestamp()), reverse=True)
                submit_quota = MAX_IMPERFECT_PATCHES_TOTAL - len(submitted_imperfect_ids)
                imperfects_to_submit = []
                for patch in sorted_imperfect_patches:
                    if len(imperfects_to_submit) >= submit_quota:
                        break

                    if patch.patch_key in submitted_imperfect_ids:
                        _l.info(f"Skipping already submitted imperfect patch %s", patch.patch_key)
                        continue

                    imperfects_to_submit.append(patch)
                    submitted_imperfect_ids.append(patch.patch_key)

                if imperfects_to_submit:
                    _l.info("Found %d new imperfect patches to submit", len(imperfects_to_submit))
                    patches_to_submit.extend(imperfects_to_submit)
                    _l.info("Uploading new imperfect patches to submission node: %s", submitted_imperfect_ids)
                    PatchergSubmissionNode.upload_node(pdt_project_id=project_id, submitted_imperfect_patches=submitted_imperfect_ids)
        else:
            _l.info("No submission node found, skipping check for now!")


        crashing_inputs_to_submit = list(harness_inputs.values())
        _l.info(f"Found {len(patches_to_submit)} patches to submit and {len(crashing_inputs_to_submit)} crashing inputs to submit")
        # Write crashing inputs to edicts
        with logging_timed_context("Writing patch and crash submission edicts"):
            for harness_input in crashing_inputs_to_submit:
                _l.info(f"Submitting crashing input {harness_input.content_hash}")
                try:
                    write_crash_submission_edict(harness_input, crash_submission_edict_path)
                except Exception as e:
                    _l.error("Error writing crash submission edict for %s", harness_input.content_hash, exc_info=True)
                    continue
            for patch in patches_to_submit:
                _l.info(f"Submitting patch {patch.patch_key}")
                try:
                    write_patch_submission_edict(patch, patch_submission_edict_path)
                except Exception as e:
                    _l.error(f"Error writing patch submission edict for %s", patch.patch_key, exc_info=True)
                    continue
        time.sleep(30)




def main():
    parser = argparse.ArgumentParser(description="""
        The PatcherG CLI.
        """,
                                     epilog="""
        Examples:
        patcherg --version
        """,
                                     )
    parser.add_argument('--project-id', type=str, help='The project id to use for the analysis graph', required=True)
    parser.add_argument("--version", "-v", action="version", version=patcherg.__version__)
    parser.add_argument('--local-run', action='store_true', default=False, help='Whether to run the process locally')
    parser.add_argument('--patch-request-meta', type=str, help='Path to the patch meta request folder', default=None)
    parser.add_argument('--patch-bypass-requests', type=str, help='Patch request id', default=None)

    parser.add_argument('--crash-submission-edicts', type=Path, required=True)
    parser.add_argument('--patch-submission-edicts', type=Path, required=True,
                        help='Path to the patch submission edicts folder. This is where the patches will be written to.')
    parser.add_argument('--task-type', type=str, required=True, help="Mode (full or delta) patcherg is running in")

    args = parser.parse_args()
    patch_request_meta = None
    if args.patch_request_meta:
        patch_request_meta = Path(args.patch_request_meta)
    patch_bypass_requests = None
    if args.patch_bypass_requests:
        patch_bypass_requests = Path(args.patch_bypass_requests)
    local_run = args.local_run

    run(
        args.project_id,
        patch_request_meta,
        patch_bypass_requests,
        args.patch_submission_edicts,
        args.crash_submission_edicts,
        args.task_type,
    )



if __name__ == "__main__":
    main()
