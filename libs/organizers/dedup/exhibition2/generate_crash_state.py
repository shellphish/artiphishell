"""
generate_crash_state.py uses Clusterfuzz's internal tooling to generate both crash
states and crash summaries given fuzzer outputs. Crash states are used for deduplication
by clusterfuzz. In order to run it, you need a fuzzer output to use. You can get these
from running OSS-Fuzz's helper.py reproduce with an input to a fuzzing harness: it will
spew one out for you.
Be advised that crash states frequently contain newlines. That's OK, and expected
behaviour.
This also serves as a sample usage of our utilities. You should feel free to script with
them as well.
If you're not sure what crash states are supposed to look like, that's OK: one has been
provided as an example at sample_fuzz_output.txt. It should look pretty familiar.
This script will also generate something called an 'instrumentation key' when
applicable. For certain fuzzer outputs, we use this concept of isntrumentation key to
deduplicate when we detect that the fuzzer has instrumented all of the same methods from
top to bottom. The sample_fuzz_output.txt that was provided has such lines, and so you
will see a sample instrumentation key output from it!
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from clusterfuzz._internal.crash_analysis.crash_result import CrashResult

# The pattern we use to yank "Instrumented ..." lines. One sample line:
# INFO: Instrumented org.apache.commons.compress.archivers.ArchiveInputStream (took 9 ms, size +9%)
# Our regex will yank only
# org.apache.commons.compress.archivers.ArchiveInputStream
# INSTRUMENTATION_PATTERN = re.compile(pattern=r".*Instrumented\s(?P<fragment>.*)\s\(.*")
INSTRUMENTATION_PATTERN = re.compile(
    pattern=r"Instrumented\s(?P<fragment>[A-Za-z0-9\.]*)\s"
)

_this_directory = os.path.dirname(os.path.realpath(__file__))


def instrumentation_key_from_fuzz_artefact(fuzz_artefact: str) -> str | None:
    """
    Given a fuzz artefact, create a key that can be used to identify it by its
    instrumentation pattern
    """
    matches = INSTRUMENTATION_PATTERN.findall(fuzz_artefact)
    return "\n".join(sorted(matches)) if matches else None


def crash_state_from_fuzz_artefact(
    fuzz_artefact: str,
    return_code: int | None = None,
    crash_time: datetime | None = None,
    unexpected_crash: bool = False,
    custom_stack_frame_ignore_regexes: list[str] | None = None,
) -> str:
    """
    Given an output fuzz artefact ( actual log output from running a fuzzer ), generate
    the clusterfuzz 'crash state' for that fuzz output.
    You may include return_code, crash_time, and whether the crash was unexpected.
    If the project you're targeting has stack_frame_ignore_regexes defined in its
    project.yaml file, you should include them as a list of strings.
    """

    # NOTE / JANK
    # project.yaml is so deeply embedded into clusterfuzz that it's wildly difficult to
    # ignore. In this particular case, it would appear that the only reason why we're
    # using it at all is to fetch stack from ignore regexes for the project that we're
    # looking at. Because it's not likely that we'll be able to decouple this setup in
    # code that isn't ours, we just heavily monkey-patch clusterfuzz's code instead,
    # substituting our own reality.
    # This puts the onus on the caller to know which ( if any ) regexes are defined for
    # the targeted project.
    # The final mock -- ...local_config.ProjectConfig.get -- is the most meaningful one,
    # and allows us to substitute our input list.

    custom_stack_frame_ignore_regexes = custom_stack_frame_ignore_regexes or []
    with (
        patch(
            "clusterfuzz._internal.system.environment.get_config_directory"
        ) as mock_get_config_directory,
        patch(
            "clusterfuzz._internal.config.local_config._validate_root"
        ) as mock_validate_root,
        patch(
            "clusterfuzz._internal.config.local_config.ProjectConfig.get"
        ) as mock_get_config,
    ):
        mock_get_config.return_value = custom_stack_frame_ignore_regexes
        mock_get_config_directory.return_value = _this_directory
        mock_validate_root.return_value = True

        return CrashResult(
            return_code=return_code or 0,
            crash_time=crash_time,
            output=fuzz_artefact,
            unexpected_crash=unexpected_crash,
        ).get_state()


def main() -> None:
    """
    Run the crash state and summary generation.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Generate a crash state and a crash summary given a fuzzer harness' output."
        )
    )
    parser.add_argument(
        "-i",
        "--input-file",
        required=True,
        help=(
            "The file where we'll find the fuzz outputs from which we'll load the "
            "crash state and summary."
        ),
    )
    parser.add_argument(
        "-o",
        "--output-file",
        required=False,
        help="The file where we'll write the crash state and summary ( as JSON ).",
    )
    args = parser.parse_args()
    input_path = Path(args.input_file)

    if not input_path.exists() and input_path.is_file():
        print(f"Hmm, I don't see a file at `{input_path}`. Double check your entry.")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as file_handle:
        data = file_handle.read()
    crash_state = crash_state_from_fuzz_artefact(fuzz_artefact=data)
    instrumentation_key = instrumentation_key_from_fuzz_artefact(fuzz_artefact=data)
    print("=~" * 20)
    print()
    print("Crash State:")
    print(crash_state)
    print("=~" * 20)

    print("=~" * 20)
    print()
    print("Instrumentation Key:")
    print(instrumentation_key)
    print("=~" * 20)

    if args.output_file:
        output_path = Path(args.output_file)
        print(f"Writing these to disk at `{output_path}`.")
        with open(output_path, "w", encoding="utf-8") as file_handle:
            json.dump(
                {
                    "crash_state": crash_state,
                    "instrumentation_key": instrumentation_key,
                },
                file_handle,
            )
    else:
        print("_Not_ writing to disk.")


if __name__ == "__main__":
    main()
