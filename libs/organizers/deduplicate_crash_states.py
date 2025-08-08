#!/shellphish/libs/organizers/dedup/exhibition2/venv/bin/python3

from typing import Dict
from shellphish_crs_utils.models.crs_reports import DedupInfo, DedupInfoKind
from dedup.exhibition2.deduplicate_povs import ClusterfuzzDeduplicator, InstrumentationKeyDeduplicator, ExportPoV, CrashComparer
import sys
import json

CLUSTERFUZZ_DEDUPLICATOR = ClusterfuzzDeduplicator()
INSTRUMENTATION_KEY_DEDUPLICATOR = InstrumentationKeyDeduplicator()

def crash_state_compare(
    crash_state_a: str | None, crash_state_b: str | None
) -> bool:
    """
    Compare two crash states for equality.
    Args:
        crash_state_a (str | None): The first crash state.
        crash_state_b (str | None): The second crash state.
    Returns:
        bool: True if the two crash states are equal, False otherwise.
    """
    return CrashComparer(crash_state_a, crash_state_b).is_similar()

def instrumentation_key_compare(
    instrumentation_key_a: str | None, instrumentation_key_b: str | None
) -> bool:
    """
    Compare two instrumentation keys for equality.
    Args:
        instrumentation_key_a (str | None): The first instrumentation key.
        instrumentation_key_b (str | None): The second instrumentation key.
    Returns:
        bool: True if the two instrumentation keys are equal, False otherwise.
    """
    if (instrumentation_key_a is None) != (instrumentation_key_b is None):
        return False
    return CrashComparer(
        instrumentation_key_a, instrumentation_key_b
    ).is_similar()

def are_dedup_infos_duplicates(dedup_info_a: Dict[str, str], dedup_info_b: Dict[str, str]) -> bool:
    """
    Compare two DedupInfo objects for equality.

    Args:
        dedup_info_a (DedupInfo): The first DedupInfo object.
        dedup_info_b (DedupInfo): The second DedupInfo object.

    Returns:
        bool: True if the two DedupInfo objects are equal, False otherwise.
    """
    instrumentation_key_a = dedup_info_a.get('instrumentation_key', None)
    instrumentation_key_b = dedup_info_b.get('instrumentation_key', None)
    return crash_state_compare(dedup_info_a['crash_state'], dedup_info_b['crash_state']) \
        or instrumentation_key_compare(instrumentation_key_a, instrumentation_key_b)

def main():
    """
    Main function to read JSON input from stdin, compare DedupInfo objects, and print the result.
    """
    with open(sys.argv[1], 'r') as file:
        input_data = json.load(file)

    dedup_searched = input_data['to_find']
    dedups_to_compare = input_data['to_compare']

    # input_data is a list of DedupInfo object pairs that should be compared, we must return a list of booleans
    results = [are_dedup_infos_duplicates(dedup_searched, dedup) for dedup in dedups_to_compare]
    with open(sys.argv[2], 'w') as file:
        json.dump(results, file, indent=2)

if __name__ == "__main__":
    main()
