import json
import os
import logging
from pathlib import Path

import yaml

from kumushi.data import Program
from patchery import Patch
from patchery.utils import fuzzy_hash, compare_hashes, md5_hash

from itertools import combinations
from typing import Dict, List, Set

_DEBUG = 0
GROUND_TRUTH_PATH = os.getenv("GROUND_TRUTH_PATH", None)
_l = logging.getLogger(__name__)

class PatchDeduplicator:
    SIMILARITY_THRESHOLD = 0.9

    """
    Deduplicates patches based on their content.
    """
    def __init__(self, patches: list[Patch], program: Program | None = None):
        self.patches = patches
        self._program = program

    @staticmethod
    def bucket_by_function_names(patches) -> dict[str, list[Patch]]:
        # first bucket by which functions are modified in a patch
        patch_by_func_names = {}
        for patch in patches:
            func_names = []
            for func_patch in patch.patched_functions:
                func_names.append(func_patch.function_name)

            func_names = tuple(func_names)
            if func_names not in patch_by_func_names:
                # first search for a possible overlap
                for other_func_names in patch_by_func_names.keys():
                    if set(other_func_names).intersection(set(func_names)):
                        patch_by_func_names[other_func_names].append(patch)
                        break
                else:
                    # no overlap found, create a new bucket
                    patch_by_func_names[func_names] = []
                    patch_by_func_names[func_names].append(patch)
            else:
                # we have a bucket for this function names, just add the patch
                patch_by_func_names[func_names].append(patch)

        return patch_by_func_names

    @staticmethod
    def _hash_patch(patch: "Patch") -> bytes:
        """Return the fuzzy-hash of the patch diff (skip first two context lines)."""
        diff_text = "\n".join(patch.diff.splitlines()[2:])
        return fuzzy_hash(diff_text.encode("utf-8"))

    @staticmethod
    def _group_indices(hashes: List[bytes], threshold: float) -> List[List[int]]:
        """
        Partition indices into the largest possible groups in which *all*
        members are pair-wise similar (distance ≤ `threshold`).

        Args:
            hashes:   fuzzy-hash bytes for the patches of one function
            threshold: maximum distance at which two patches are considered similar

        Returns:
            A list of buckets, each bucket a list of patch indices.
        """
        n = len(hashes)
        # --- 1. build an O(n²) boolean similarity matrix -------------------------
        similar = [[False] * n for _ in range(n)]
        for i, j in combinations(range(n), 2):
            dist = compare_hashes(hashes[i], hashes[j], normalize=True)
            if dist <= threshold:
                similar[i][j] = similar[j][i] = True
        for i in range(n):
            similar[i][i] = True  # a patch is always similar to itself

        # --- 2. helper: how many neighbours each node has ------------------------
        degree = [sum(row) - 1 for row in similar]  # exclude self-loop

        # --- 3. greedily carve out the largest cliques ---------------------------
        ungrouped: Set[int] = set(range(n))
        buckets: List[List[int]] = []

        while ungrouped:
            # start with the still-free node that has the most similar edges
            seed = max(ungrouped, key=degree.__getitem__)
            clique = {seed}
            # consider remaining nodes in descending degree order
            for node in sorted(ungrouped - {seed}, key=degree.__getitem__, reverse=True):
                if all(similar[node][member] for member in clique):
                    clique.add(node)

            buckets.append(list(clique))
            ungrouped -= clique  # remove the nodes we just assigned

        return buckets

    @staticmethod
    def bucket_by_similarity(
            patches_by_name: Dict[str, List["Patch"]],
            sim_threshold: float = 0.90,
    ) -> Dict[str, List[List["Patch"]]]:
        """
        Bucket patches *only within the same `func_name`*.
        Returns: {func_name -> list of buckets}, where each bucket is a list of Patch.
        """
        buckets_by_name: Dict[str, List[List["Patch"]]] = {}

        for func_name, patches in patches_by_name.items():
            if not patches:  # nothing to do
                continue

            if len(patches) == 1:  # only one patch → its own bucket
                buckets_by_name[func_name] = [[patches[0]]]
                continue

            # 1. hash each patch exactly once
            hashes = [PatchDeduplicator._hash_patch(p) for p in patches]

            # 2. compute similarity buckets for *this* function only
            idx_buckets = PatchDeduplicator._group_indices(hashes, sim_threshold)

            # 3. convert index buckets → patch buckets
            buckets_by_name[func_name] = [
                [patches[i] for i in bucket] for bucket in idx_buckets
            ]

        return buckets_by_name

    @staticmethod
    def _bucket_by_similarity(patches_by_name: dict[str, list[Patch]], sim_threshold=0.9) -> list[list[Patch]]:
        bucketed_patches = []
        for func_name, patches in patches_by_name.items():
            if len(patches) == 1:
                # no duplicates, just add the patch
                bucketed_patches += patches
                continue

            patch_hashes = []
            for patch in patches:
                diff_text = "\n".join(patch.diff.splitlines()[2:])
                patch_hash = fuzzy_hash(diff_text.encode("utf-8"))
                patch_hashes.append((patch, patch_hash))

            duplicates = []
            unique_patches = []
            updates = True
            while updates:
                updates = False
                for patch, patch_hash in list(patch_hashes):
                    for other_patch, other_hash in list(patch_hashes):
                        if patch is other_patch:
                            continue

                        # compare the hashes
                        similarity_score = compare_hashes(patch_hash, other_hash, normalize=True)
                        if similarity_score < sim_threshold:
                            # we have a duplicate
                            duplicates.append((patch, other_patch))
                        else:
                            # we have a unique patch
                            unique_patches.append(patch)

                        patch_hashes.remove((patch, patch_hash))
                        patch_hashes.remove((other_patch, other_hash))
                        updates = True
                        break

                    if updates:
                        break

            if unique_patches:
                bucketed_patches.append((unique_patches,))
            if duplicates:
                bucketed_patches.append(duplicates)

        return bucketed_patches

    def bucket_by_metadata(
        self,
        pre_bucket_patches: list[list[Patch]],
        key: str = "poi_report_id",
    ) -> list[list[Patch]]:
        """
        Merge buckets when any patch in one bucket shares the same `key`
        (default: 'poi_report_id') with any patch in another bucket.
        """
        bucketed: list[list[Patch]] = []

        for bucket in pre_bucket_patches:
            merged = False
            for other_bucket in bucketed:
                # any() short-circuits as soon as we find a match
                if any(
                    p.metadata.get(key) == op.metadata.get(key)
                    for p in bucket
                    for op in other_bucket
                ):
                    other_bucket.extend(bucket)  # <-- in-place merge fixes the loss
                    merged = True
                    break  # one merge is enough

            if not merged:
                bucketed.append(bucket[:])  # shallow-copy to stay side-effect-free

        return bucketed

    def deduplicate(self) -> list[list[Patch]]:
        patch_by_func_names = self.bucket_by_function_names(self.patches)
        patch_by_similarity = self.bucket_by_similarity(patch_by_func_names, sim_threshold=self.SIMILARITY_THRESHOLD)
        sim_buckets = [[item for sublist in x for item in sublist] for x in patch_by_similarity.values()]

        # check if we have metadata
        first_patch = self.patches[0]
        if first_patch.metadata:
            bucketed_patches = self.bucket_by_metadata(sim_buckets)
        else:
            # no metadata, just return the patches
            bucketed_patches = sim_buckets

        if _DEBUG:
            self._check_ground_truth(bucketed_patches)

        return bucketed_patches

    def _check_ground_truth(self, bucketed_patches: list[list[Patch]]):
        truth_json_path = GROUND_TRUTH_PATH
        if truth_json_path is None or not Path(truth_json_path).exists():
            _l.debug("Ground truth json file does not exist")
            return

        with open(truth_json_path, "r") as truth_file:
            truth_data = json.load(truth_file)

        poi_id_to_cpv = {}
        for path, cpv_id in truth_data.items():
            poi_id = Path(path).stem
            poi_id_to_cpv[poi_id] = cpv_id

        buckets_of_cpvs = []
        for bucket in bucketed_patches:
            cpv_data = []
            for patch in bucket:
                poi_id = patch.metadata.get("poi_report_id")
                if poi_id:
                    cpv_id = poi_id_to_cpv.get(poi_id, None)
                    cpv_data.append(cpv_id)
            buckets_of_cpvs.append(cpv_data)


    @classmethod
    def dedupe_many_aicc_patch_dirs(
        cls,
        patches_dir: Path,
        patch_metadata_dir: Path | None = None,
        **kwargs,
    ):
        deduplicator = cls.from_patch_dir(patches_dir, patch_metadata_dir=patch_metadata_dir)
        patch_buckets = deduplicator.deduplicate()
        return patch_buckets


    @classmethod
    def from_patch_dir(cls, patch_dir: Path, patch_metadata_dir: Path | None = None, **kwargs):
        patch_dir = Path(patch_dir).absolute()
        patch_metadata = {}
        if patch_metadata_dir:
            patch_metadata_dir = Path(patch_metadata_dir).absolute()
            if patch_metadata_dir.exists() and patch_metadata_dir.is_dir():
                # load the metadata from the directory
                for file in patch_metadata_dir.glob("*.yaml"):
                    with open(file, "r") as f:
                        metadata = yaml.unsafe_load(f.read())
                    patch_metadata[file.stem] = metadata


        # we select patches in the dir based on if they have metadata
        patch_files = []
        if patch_metadata:
            for patch_id in patch_metadata:
                patch_file = patch_dir / patch_id
                if patch_file.exists():
                    patch_files.append(patch_file)
        else:
            # no metadata, just select all files in the directory
            patch_files = [p for p in patch_dir.glob("*") if p.is_file() and p.suffix not in [".json", ".yaml"]]

        # find all the patches
        patches = []
        for file in patch_files:
            # we have a patch file
            patch = Patch.from_git_diff(file, metadata=patch_metadata.get(file.stem, None))
            patches.append(patch)

        return cls(patches, **kwargs)
