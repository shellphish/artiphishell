import logging
import math
import time
import yaml
from collections import defaultdict
from pathlib import Path
from typing import Optional, List, Dict, Set

from ..data import Patch, ProgramInfo

_l = logging.getLogger(__name__)


class PatchRanker:
    INVALID_PATCH_PENALTY = 1_000_000
    RANK_FILE_PREFIX = "patch_ranks_"

    def __init__(
        self,
        patches: List[Patch],
        prog_info: Optional[ProgramInfo] = None,
        prev_crash_inputs: Dict[Patch, List[Path]] = None,
        new_crash_inputs: Dict[Patch, List[Path]] = None,
        rank_output_dir: Optional[Path] = None,
        delay_scoring: bool = False,
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

        if not delay_scoring:
            if self._continuous:
                self.continuous_ranking()
            else:
                self.score_patches()

    def continuous_ranking(self):
        """
        Continuously rank patches as new crash reports come in
        """
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            self.score_patches()
            time.sleep(self.wait_time)

    def score_patches(self):
        _l.info(f"Scoring vds_id={self.vds_id} patches...")
        for patch in self._patches:
            self.scored_patches[patch] = self.score_patch_badness(patch)

        self.ranked_patches = sorted(self.scored_patches, key=lambda x: self.scored_patches[x])
        timestamp = int(time.time_ns())
        output_yaml_data = {
            "ranks": [str(p.file_path) for p in self.ranked_patches],
            "invalidated_patches": [str(p.file_path) for p in self.invalidated_patches],
            "patch_info": {str(p.file_path): self.scored_patches[p] for p in self.ranked_patches},
            "timestamp": timestamp,
            "vds_id": self.vds_id
        }

        if self._rank_output_dir is not None:
            output_file = self._rank_output_dir / f"{self.RANK_FILE_PREFIX}{timestamp}.yaml"
            with open(output_file, "w") as fp:
                yaml.dump(output_yaml_data, fp)

            _l.info(f"Ranking output written to {output_file}")

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
        added = patch.patched_file_data.added or 0
        removed = patch.patched_file_data.removed or 0
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

        patch_crashes_by_vds = defaultdict(dict)
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

            pdt_vds_id = metadata.get("pdt_vds_id", None)
            if pdt_vds_id is None:
                _l.error(f"Patch {patch_file} has no pdt_vds_id, skipped for ranking!")
                continue

            patch = Patch.from_git_diff(patch_file)

            still_crashing = []
            all_crashes = []
            prev_crashing_files = list(previous_crashes_dir.iterdir())
            for prev_crash_info_file in prev_crashing_files:
                try:
                    prev_crash_info = yaml.safe_load(prev_crash_info_file.read_text())
                except Exception as e:
                    _l.error(f"Error loading crash info file {prev_crash_info_file}: {e}, skipped for ranking!")
                    continue

                patch_id = prev_crash_info.get("patch_id", None)
                has_crashed = prev_crash_info.get("still_crashing", False)
                if patch_id == patch_file.name:
                    all_crashes.append(prev_crash_info_file)
                    if has_crashed:
                        still_crashing.append(prev_crash_info_file)

            _l.info(f"Patch {patch_file.name} has {len(still_crashing)} still crashing inputs out of {len(all_crashes)}")
            still_crashing_percent = 0 if not all_crashes else len(still_crashing) / len(all_crashes)
            patch_crashes_by_vds[pdt_vds_id][patch] = still_crashing_percent

        rankers = []
        for pdt_vds_id, crash_perc_by_patch in patch_crashes_by_vds.items():
            ranker = cls(
                list(crash_perc_by_patch.keys()),
                continuous=continuous,
                rank_output_dir=rank_output_dir,
                wait_time=wait_time,
                timeout=timeout,
                vds_id=pdt_vds_id,
                still_crashing_percent=crash_perc_by_patch,
            )
            _l.info("Ranked %d patches for VDS %s", len(ranker.ranked_patches), pdt_vds_id)
            rankers.append(ranker)

        return rankers

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
