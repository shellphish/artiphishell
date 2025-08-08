from pathlib import Path
from dataclasses import dataclass, field
from shellphish_crs_utils.models.crs_reports import CrashingInputMetadata

class QuickSeedHarnessInfo(CrashingInputMetadata):
    harness_source_path: Path
    harness_benign_dir: Path
    harness_crash_dir: Path


@dataclass
class QuickSeedConfig:
    # for nap mode
    nap_mode: bool = True
    # What is the next N minute mark we are waking up from the nap
    nap_duration: int = 5 # this is in minutes
    # If we are in nap mode, we will wait N seconds before trying to wake up
    nap_snoring: int = 60
    # If we wake up N times in a row and there is no budget, we kill the component.
    nap_becomes_death_after: int = 20

    # backup models when we hit rate limits
    backup_models: list = field(default_factory=lambda: [
        "o4-mini",
        "claude-4-sonnet"
    ])

    max_retry_on_other_exception: int = 10

    # The number of every how many sinks we do the reranking by whether starts with sources
    # For example, if we have a list [paths_for_sink_1, paths_for_sink_2, ...]
    # Every {rerank_by_source_rotation_count} sinks we want to put the paths_for_sink_i that all paths start with sources in the beginning and others the second
    rerank_by_source_rotation_count: int = 50


Config = QuickSeedConfig()