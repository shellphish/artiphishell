#!/usr/bin/env python3
"""
Crash Analyzer Script:

- 0 => No significant crash recognized
- 211 => Recognized sanitizer crash
- 212 => Recognized non-sanitizer but notable crash
- 213 => Recognized sanitizer signature despite unrecognized return code (error)
- 214 => Recognized error in reproducing

Normal usage and the unit tests load the config from ./ossfuzz_config.yaml unless
overridden by --config_path

Ex:
  python3 crash_analyzer.py \
      --engine libfuzzer \
      --sanitizer address \
      --return_code 77 \
      --stderr_path /tmp/fuzzer_stderr.txt \
      --stdout_path /tmp/fuzzer_stdout.txt \
      --config_path /path/to/ossfuzz_config.yaml

"""
import json
import argparse
import re
import sys

import yaml


def parse_args():
    """Parse input arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze crashes with external config."
    )
    parser.add_argument(
        "--engine",
        required=True,
        help="Engine name {libfuzzer}",
    )
    parser.add_argument(
        "--sanitizer",
        required=True,
        help="Sanitizer name {address,memory,undefined,thread}",
    )
    parser.add_argument(
        "--return_code", type=int, required=True, help="Return code from the harness"
    )  # Assume this is being propogated now from closing aixcc-challenges/oss-fuzz-aixcc #27
    parser.add_argument(
        "--stderr_path", required=True, help="Path to file containing stderr output"
    )
    parser.add_argument(
        "--stdout_path", required=True, help="Path to file containing stdout output"
    )
    parser.add_argument(
        "--config_path",
        default="ossfuzz_config.yaml",
        help="Path to the YAML config file (default: ossfuzz_config.yaml).",
    )
    parser.add_argument(
        '--output_path',
        default='crash_analysis_output.json',
        help='Path to the output JSON file (default: crash_analysis_output.json).'
    )
    args, unknown = parser.parse_known_args()
    return args, unknown


def read_file(path: str) -> str:
    """Read file"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def load_config(config_path: str) -> dict:
    """Load config"""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def determine_misc(
    config: dict, return_code: int, stderr_text: str, stdout_text: str
) -> tuple[str | None, str | None]:
    """
    Parse results against the misc_errors section of the config.
    """
    combined = stderr_text + "\n" + stdout_text
    misc = config.get("misc_errors", {})
    codes_map = misc.get("codes", {})
    result = codes_map.get(return_code, None)

    if result:
        return result.get("msg"), result.get(
            "significance", 1
        )  # 1 indicates an error if significance is not found

    patterns = misc.get("patterns", [])
    for item in patterns:
        error_type = item.get("error_type")
        pattern = item.get("regex")
        if error_type and pattern and re.search(pattern, combined):
            return f"Error: {error_type}", item.get(
                "significance", 1
            )  # 1 indicates an error if significance is not found

    # if configuration did not catch anything
    return None, None


# pylint: disable=too-many-arguments
def interpret_return_code(
    config: dict,
    engine: str,
    return_code: int,
    stderr_text: str,
    stdout_text: str,
    sanitizer_found: str,
) -> tuple[str | None, str | None]:
    """
    Interpret the results against the standard engine + sanitizer parsing config.
    """
    engine_lower = engine.lower()
    result = None
    sig = None

    engine_entries = config.get("engines", [])
    engines = [e.get("name", "").lower() for e in engine_entries]

    if engine_lower not in engines:
        raise ValueError(f"Invalid engine: {engine_lower}")

    for e in engine_entries:
        if e.get("name", "").lower() == engine_lower:
            codes_map = e.get("codes", {})
            result = codes_map.get(return_code, None)
            if result:
                if result.get("require_sanitizer") and sanitizer_found is None:
                    result = (
                        None  # do not match if sanitizer was required but not found
                    )
                else:
                    return result.get("msg"), result.get(
                        "significance", 1
                    )  # 1 indicates an error if significance is not found

    result_msg = None

    if result is None:
        result_msg, sig = determine_misc(config, return_code, stderr_text, stdout_text)

    if result_msg is None:
        result_msg = (
            f"Unhandled case: engine {engine}, exitcode {return_code}, "
            f"sanitizer-detected: {sanitizer_found}"
        )

    return result_msg, sig


def detect_sanitizer_crash(
    config: dict, sanitizer: str, stderr_text: str, stdout_text: str
) -> str | None:
    """
    Match stdin and stderr against sanitizer regex in config.
    """
    combined = stderr_text + "\n" + stdout_text
    sanitizer_data = config.get("sanitizers", {}).get(sanitizer, {})
    patterns = sanitizer_data.get("patterns", [])

    # Detect the first pattern that matches, top-down
    for item in patterns:
        crash_type = item.get("crash_type")
        pattern = item.get("regex")
        if crash_type and pattern and re.search(pattern, combined):
            return f"{sanitizer.capitalize()} sanitizer crash: {crash_type}"

    return None


def run_analysis(args):
    """
    Run the analysis of the resulting exit code and stdin/stderr information
    from the reproduce event.
    """
    config = load_config(args.config_path)

    stderr_text = read_file(args.stderr_path)
    stdout_text = read_file(args.stdout_path)

    sanitizer_found = detect_sanitizer_crash(
        config, args.sanitizer, stderr_text, stdout_text
    )
    print(f"[DEBUG] SANITIZER DETECTION: {sanitizer_found}.")

    code_label, sig = interpret_return_code(
        config, args.engine, args.return_code, stderr_text, stdout_text, sanitizer_found
    )
    print(f"[DEBUG] INTERPRETATION: sig={sig} msg={code_label}.")

    if sig is not None:
        return (code_label, sig)

    if sanitizer_found:
        return (
            f"ERROR: Found sanitizer signature despite "
            f"unrecognized return code or error : {sanitizer_found}",
            213,
        )

    return (code_label, 0)


if __name__ == "__main__":
    parsed_args, parsed_unknown = parse_args()
    output, exit_code = run_analysis(parsed_args)
    with open(parsed_args.output_path, "w", encoding="utf-8") as output_file:
        json.dump(
            {"message": output, "significance": exit_code},
            output_file,
            indent=2,
        )
    sys.exit(exit_code)
