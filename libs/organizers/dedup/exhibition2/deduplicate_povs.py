"""
PoV Deduplication as a script
This script allows you to see how our scoring pipeline deduplicates PoVs. This serves as
both a usage sample for our internal system as well as a utility for your use. You can
find a sample input for this file at sample_deduplication_input.json.

If you're having trouble generating "crash states" and "instrumentation keys" to feed
into your own inputs, please see the adjacent script, 'generate_crash_state.py'.
"""

import argparse
import json
import sys
from abc import ABC, abstractmethod
from enum import StrEnum, auto
from itertools import permutations
from json import JSONDecodeError
from pathlib import Path
from typing import ClassVar, Sequence, cast

import pydantic
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from pydantic import ValidationError
from typing_extensions import TypedDict


# pylint: disable=too-few-public-methods
class PoVDuplicationReasons(StrEnum):
    """
    Reasons why a PoV may be considered a duplicate.
    """

    POV_COPY = auto()
    EXACT_MATCH = auto()
    CLUSTERFUZZ_COMPARE = auto()
    SAME_FUZZER_INSTRUMENTATION_PATTERN = auto()


# pylint: disable=too-few-public-methods
class ExportPoV(TypedDict):
    """
    A stripped-down dictionary that represents a PoV submission.
    """

    task_uuid: str
    crash_state: str | None
    instrumentation_key: str | None
    uuid: str
    testcase_sha256: str | None
    build_sanitizer: str
    build_architecture: str
    fuzzer_name: str


export_pov_adapter = pydantic.TypeAdapter(ExportPoV)


# pylint: disable=too-few-public-methods
class PovAbstractDeduplicator(ABC):
    """
    A base for PoV deduplicators. Deduplicators are machines that accept a pair of
    PoVs and determine whether or not they're duplicates of one-another.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    duplication_reason: PoVDuplicationReasons

    @abstractmethod
    def is_duplicate(self, pov_a: ExportPoV, pov_b: ExportPoV) -> bool:
        """
        Given two PoVs pov_a and pov_b, determine whether or not pov_b is a duplicate of
        pov_b. If it is, return True, otherwise return False.
        """
        raise NotImplementedError  # Abstract method, to be implemented by subclasses


class ClusterfuzzDeduplicator(PovAbstractDeduplicator):
    """
    Utilizes the same logic that clusterfuzz uses to deduplicate PoVs.
    """

    name = "ClusterFuzz"
    description = (
        "Check if PoVs are duplicate based on ClusterFuzz's opinion using pre-computed "
        "crash state strings"
    )
    duplication_reason = PoVDuplicationReasons.CLUSTERFUZZ_COMPARE

    def is_duplicate(self, pov_a: ExportPoV, pov_b: ExportPoV) -> bool:
        """
        Using clusterfuzz's logic, determines whether pov_b is a duplicate of pov_b.
        """

        # Instantiate a CrashComparer using the crash states...
        comparer = CrashComparer(pov_a["crash_state"], pov_b["crash_state"])
        # Return the result of CrashComparer's is_similar(). NOTE: This deals with
        # cases of null crash states for you, and you don't have to think about it.
        # We should use ClusterFuzz's determination, not our own.
        return comparer.is_similar()


class InstrumentationKeyDeduplicator(PovAbstractDeduplicator):
    """
    Determines duplicates by examining their instrumentation keys, _if and only if_
    they have them.
    """

    name = "InstrumentationKeyDeduplicator"
    description = (
        "Check if PoVs are duplicates because they have the same instrumentation keys."
    )
    duplication_reason = PoVDuplicationReasons.SAME_FUZZER_INSTRUMENTATION_PATTERN

    def is_duplicate(self, pov_a: ExportPoV, pov_b: ExportPoV) -> bool:
        """
        Using clusterfuzz's fuzzy matching from crash comparer, determine whether
        pov_b is a duplicate of pov_a based on their instrumentation keys.
        """
        comparer = CrashComparer(
            pov_a.get("instrumentation_key"), pov_b.get("instrumentation_key")
        )
        return comparer.is_similar()


class PoVIsMatch(PovAbstractDeduplicator):
    """
    Deduplicator for determining whether one PoV's fields match another's fields.
    """

    name: ClassVar[str] = "IsMatch"
    description: ClassVar[str] = "Check if PoV fields match another PoV"
    duplication_reason: PoVDuplicationReasons = PoVDuplicationReasons.EXACT_MATCH

    def is_duplicate(self, pov_a: ExportPoV, pov_b: ExportPoV) -> bool:
        """
        Merely check a few field values.
        """
        return (
            pov_a["task_uuid"] == pov_b["task_uuid"]
            and pov_a["testcase_sha256"] == pov_b["testcase_sha256"]
            and pov_a["build_sanitizer"] == pov_b["build_sanitizer"]
            and pov_a["build_architecture"] == pov_b["build_architecture"]
            and pov_a["fuzzer_name"] == pov_b["fuzzer_name"]
        )


class PoVIsCopy(PovAbstractDeduplicator):
    """
    Deduplicator for determining whether a PoV is simply a copy of another.
    """

    name: ClassVar[str] = "IsCopy"
    description: ClassVar[str] = "Check if PoV is copy of other PoV"
    duplication_reason: PoVDuplicationReasons = PoVDuplicationReasons.POV_COPY

    def is_duplicate(self, pov_a: ExportPoV, pov_b: ExportPoV) -> bool:
        return pov_a == pov_b

    def __str__(self) -> str:
        return self.name


class PovDeduplicator:
    """
    Class which holds the list of deduplicators that are used on PoVs in the scoring
    pipeline.
    """

    dedup_list: list[PovAbstractDeduplicator] = [
        PoVIsCopy(),
        PoVIsMatch(),
        ClusterfuzzDeduplicator(),
        InstrumentationKeyDeduplicator(),
    ]

    @staticmethod
    def is_duplicate(
        pov_a: ExportPoV, pov_b: ExportPoV, deduplicator: PovAbstractDeduplicator
    ) -> bool:
        """
        Given a pair of PoVs and a deduplicator instance, determine whether or not the
        PoVs are duplicates based on the opinion of the deduplicator instance.
        """
        # Only create duplicate entries when Task IDs match
        if pov_a["task_uuid"] == pov_b["task_uuid"]:
            return deduplicator.is_duplicate(pov_a, pov_b)
        return False

    def deduplicate_set(self, pov_list: Sequence[ExportPoV]) -> list[str]:
        """
        Given a list of PoVs, determine if they're duplicates using all of the engines
        available to us, returning a list of PoVDuplications.
        """
        print(f"Deduplicating {len(pov_list)} PoVs")

        dup_list: list[str] = []
        task_list = {p["task_uuid"] for p in pov_list}

        for t in task_list:
            povs_for_task = [p for p in pov_list if p["task_uuid"] == t]
            for pov_a, pov_b in permutations(povs_for_task, 2):
                for dup in self.dedup_list:
                    if self.is_duplicate(pov_a, pov_b, dup):
                        dup_list.append(
                            f"- PoV `{pov_a['uuid']}` duplicates PoV `{pov_b['uuid']}` "
                            f"because: {dup.duplication_reason}"
                        )

        return dup_list


def validate_dictionary_as_pov(dictionary: dict) -> bool:
    """
    Determine whether the input dictionary can be used as a PoV.
    """
    try:
        export_pov_adapter.validate_python(dictionary)
        return True
    except ValidationError as exc:
        print("Failed to validate one of your datapoints.")
        print(exc)
    return False


def from_file(file_path: Path) -> Sequence[ExportPoV]:
    """
    Attempt to load the ExportPoVs from the provided file path.
    """
    message_your_data_is_wrong = (
        "We're expecting your PoVs as an array of objects in JSON format."
    )
    with open(file_path, "r", encoding="utf-8") as file_handle:
        try:
            data = json.load(file_handle)
        except JSONDecodeError:
            print(message_your_data_is_wrong)
            sys.exit(1)

    if not isinstance(data, list):
        print(message_your_data_is_wrong)
        sys.exit(1)
    for entry in data:
        if not isinstance(entry, dict):
            print(message_your_data_is_wrong)
            sys.exit(1)
        if not validate_dictionary_as_pov(dictionary=entry):
            print(
                "Your data seems to be an array of objects, but they need to conform "
                "to the `ExportPoV` TypedDict definition. Please see the above error "
                "message to see what your data needs yet."
            )
            sys.exit(1)

    return cast(Sequence[ExportPoV], data)


def main() -> None:
    """
    Run deduplication, printin the results to the console.
    """
    parser = argparse.ArgumentParser(
        description=(
            "PoV Deduplicator: Examine how the scoring pipeline would handle your PoVs!"
        )
    )
    parser.add_argument(
        "-i",
        "--input-file",
        required=True,
        help="From where should we load the input data?",
    )
    args = parser.parse_args()
    print("Attempting to deduplicate your PoVs!")
    input_path = Path(args.input_file)
    if not input_path.exists() and input_path.is_file():
        print(f"Hmm, I don't see a file at `{input_path}`. Double check your entry.")
        sys.exit(1)
    export_povs = from_file(args.input_file)
    deduplicator = PovDeduplicator()
    duplication_messages = deduplicator.deduplicate_set(pov_list=export_povs)
    if duplication_messages:
        print(
            f"The following duplications were found 'mongst your {len(export_povs)} "
            "PoVs ..."
        )
        for message in duplication_messages:
            print(message)
    else:
        print("No duplicates were found in your input. Hooray! Good work.")


if __name__ == "__main__":
    main()
