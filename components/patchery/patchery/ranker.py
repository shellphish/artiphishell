import logging
import math
import time
import yaml
from collections import defaultdict
from pathlib import Path
from typing import Optional, List, Dict, Set

from patchery.data import Patch
from patchery.deduplicator import PatchDeduplicator
from kumushi.data import Program

from shellphish_crs_utils.models.patch import PatchRankings

_l = logging.getLogger(__name__)


class PatchRanker:
    INVALID_PATCH_PENALTY = 1_000_000
    RANK_FILE_PREFIX = "patch_ranks_"

    def __init__(
        self,
        patches: List[Patch],
        prog_info: Optional[Program] = None,
        prev_crash_inputs: Dict[Patch, List[Path]] = None,
        new_crash_inputs: Dict[Patch, List[Path]] = None,
        rank_output_dir: Optional[Path] = None,
        continuous: bool = False,
        wait_time: int = 10,
        timeout: int = 1 * 60,
        vds_id=None,
        still_crashing_percent: Optional[Dict[Patch, float]] = None,
    ):
        self._patches = patches
        self._prog_info = prog_info
        self._continuous = continuous
        self.wait_time = wait_time
        self.timeout = timeout
        self.vds_id = vds_id

        self._prev_crash_inputs = defaultdict(list)
        if prev_crash_inputs:
            self._prev_crash_inputs.update(prev_crash_inputs)

        self._new_crash_inputs = defaultdict(list)
        if new_crash_inputs:
            self._new_crash_inputs.update(new_crash_inputs)

        self.still_crashing_percent = defaultdict(float)
        if still_crashing_percent:
            self.still_crashing_percent.update(still_crashing_percent)

        self._rank_output_dir = Path(rank_output_dir) if rank_output_dir is not None else None

        # output of the ranking
        self.scored_patches = {}
        self.ranked_patches = []
        self.invalidated_patches: Set[Patch] = set()

    def continuous_ranking(self):
        """
        Continuously rank patches as new crash reports come in
        """
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            self.score_patches()
            time.sleep(self.wait_time)

    def score_patches(self):
        for patch in self._patches:
            self.scored_patches[patch] = self.score_patch_badness(patch)

        self.ranked_patches = sorted(self.scored_patches, key=lambda x: self.scored_patches[x])
        timestamp = int(time.time_ns())
        output_yaml_data = {
            "ranks": [str(Path(p.file_path).stem) for p in self.ranked_patches],
            "patch_info": {str(Path(p.file_path).stem): self.scored_patches[p] for p in self.ranked_patches},
            "timestamp": timestamp,
            "poi_report_ids": list(set(p.metadata["poi_report_id"] for p in self._patches)),
        }
        return output_yaml_data

    def score_patch_badness(self, patch: Patch) -> float:
        """
        Returns a score for how bad a patch is. The lower the score, the better.

        :param patch:
        :return:
        """
        final_score = 0

        # after a certain point, we don't care about the size of the diff
        final_score += math.log(self._diff_size(patch))

        # good patches often have very few deletions
        # based on the CCS paper "A Large-Scale Empirical Study of Security Patches"
        # we punish linearly for deletions
        final_score += self._total_deletions(patch)

        # since we never know if a patch with a crash is caused because of our patch or not, we
        # can't eliminate a patch if it crashes. Instead, we just make this much higher than other metrics.
        final_score += 5 * len(self._new_crash_inputs[patch])

        # if an input that previously crashed the unpatched binary still crashes the patched binary,
        # than this is actually an invalid patch, which gets a penalty score that is HUGE
        # TODO: make this generic again after submission
        #   right now we assume everything in this is a crashing input on the patched binay
        #prev_still_crashing_inputs = self._prev_crash_inputs[patch]
        still_crashing_percent = self.still_crashing_percent[patch]
        if still_crashing_percent > 0:
            _l.warning(f"Patch {patch.file_path.name} is likely invalid because old crashes still crashes the patched binary!")
            final_score += self.INVALID_PATCH_PENALTY * still_crashing_percent
            self.invalidated_patches.add(patch)

        _l.info(f"Patch {patch.file_path.name} scored: {final_score}")
        return final_score

    def _diff_size(self, patch: Patch):
        return len(patch.diff)

    def _total_deletions(self, patch: Patch):
        added = 0
        removed = 0
        for patched_file_data in patch.patched_set_data:
            added += patched_file_data.added or 0
            removed += patched_file_data.removed or 0
        return max(0, removed - added)

    @classmethod
    def rank_many_aicc_patch_dirs(
        cls,
        patches_dir: Path,
        previous_crashes_dir: Path,
        patch_metadatas_dir: Path,
        continuous: bool = False,
        rank_output_dir: Optional[Path] = None,
        wait_time: int = 10,
        timeout: int = 1 * 60,
    ):
        """
        patchery --vds-record-path <path> --patches-dir <dir> --patch-metadatas-dir <dir> --crash-reports-dir <dir>

        How it will work:
        - a directory full of patch files that will have correspoinding metadata in another directory
        - a directory full of crash reports, which are yamls, that say which patches crash

        :return:
        """
        if not patches_dir.exists():
            patches_dir.mkdir(parents=True)
            _l.warning(f"Created patches directory {patches_dir} because it did not exist before!")

        # normalize paths
        patches_dir = Path(patches_dir).absolute()
        patch_metadatas_dir = Path(patch_metadatas_dir).absolute() if patch_metadatas_dir is not None else None
        previous_crashes_dir = Path(previous_crashes_dir).absolute() if previous_crashes_dir is not None else None

        patch_crash_percent = {}
        for patch_metadata_file in patch_metadatas_dir.iterdir():
            patch_file = patches_dir / patch_metadata_file.with_suffix("").name
            if not patch_file.exists():
                _l.error(f"Patch {patch_file} does not exist, skipped for ranking!")
                continue

            try:
                metadata = yaml.safe_load(patch_metadata_file.read_text())
            except Exception as e:
                _l.error(f"Error loading metadata file {patch_metadata_file}: {e}, skipped for ranking!")
                continue

            patch = Patch.from_git_diff(patch_file, metadata=metadata)
            # XXX: we dont have a previous crashing right now
            patch_crash_percent[patch] = 0.0

        # now we need to deduplicate the patches so we know what buckets to do ranking inside of
        deduplicator = PatchDeduplicator(list(patch_crash_percent.keys()))
        patch_buckets = deduplicator.deduplicate()
        output = {"buckets": [], "timestamp": None}
        for bucket in patch_buckets:
            crash_perc_by_patch = {patch: patch_crash_percent[patch] for patch in bucket}
            ranker: PatchRanker = cls(
                bucket,
                continuous=continuous,
                rank_output_dir=rank_output_dir,
                wait_time=wait_time,
                timeout=timeout,
                still_crashing_percent=crash_perc_by_patch,
            )
            output_dict = ranker.score_patches()
            output_dict["bucket"] = [str(p.file_path.stem) for p in bucket]
            output["buckets"].append(output_dict)

        if rank_output_dir is not None:
            timestamp = int(time.time_ns())
            output["timestamp"] = timestamp
            parsed_model = PatchRankings.model_validate(output)
            output_file = rank_output_dir / f"{PatchRanker.RANK_FILE_PREFIX}{timestamp}.yaml"

            # now dump the parsed model to a yaml file
            with open(output_file, "w") as fp:
                yaml.safe_dump(parsed_model.model_dump(), fp, default_flow_style=False, sort_keys=False)

            _l.info(f"Ranking output written to {output_file}")

        return output

    @classmethod
    def from_patch_dir(cls, patch_dir: Path):
        patch_dir = Path(patch_dir).absolute()

        # find all the patches
        patches = []
        for file in patch_dir.glob("patch*"):
            if file.suffix == ".json":
                continue

            # we have a patch file
            patch = Patch.from_git_diff(file)
            patches.append(patch)

        return cls(patches)
