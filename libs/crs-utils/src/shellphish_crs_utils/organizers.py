from collections import namedtuple
from datetime import datetime
import json
from pathlib import Path
import subprocess
import tempfile
from typing import List, Union
from enum import Enum
import yaml
import logging
from shellphish_crs_utils import ORGANIZER_LIBS_DIR
from shellphish_crs_utils.models import Field, Optional, SanitizerEnum
from shellphish_crs_utils.models.organizer_evaluation import OrganizerCrashEvaluation, SignificanceEnum

def interpret_crash_files(
        sanitizer: Union[SanitizerEnum, str],
        return_code: int,
        stderr_path: Union[str, Path],
        stdout_path: Union[str, Path],
        ) -> tuple[str, SignificanceEnum]:
    """
    Interpret the crash based on the provided parameters.
    Args:
        engine (str): The engine used for fuzzing (must be 'libfuzzer').
        sanitizer (SanitizerEnum): The sanitizer used.
        return_code (int): The return code from the fuzzing run.
        stderr_path (Union[str, Path]): Path to the stderr file.
        stdout_path (Union[str, Path]): Path to the stdout file.
    Returns:
        tuple[str, SignificanceEnum]: A tuple containing the message of the sanitization and significance.
    """

    if isinstance(sanitizer, str):
        sanitizer = SanitizerEnum(sanitizer) # ensure it's a string
    if isinstance(stderr_path, str):
        stderr_path = Path(stderr_path)
    if isinstance(stdout_path, str):
        stdout_path = Path(stdout_path)

    stdout_path = stdout_path.resolve()
    stderr_path = stderr_path.resolve()

    assert isinstance(sanitizer, SanitizerEnum), f"Invalid sanitizer type: {type(sanitizer)}, {sanitizer!r}"
    assert isinstance(stderr_path, Path), f"Invalid stderr path type: {type(stderr_path)}, {stderr_path!r}"
    assert isinstance(stdout_path, Path), f"Invalid stdout path type: {type(stdout_path)}, {stdout_path!r}"

    assert stderr_path.is_file(), f"Invalid stderr path: {stderr_path!r}"
    assert stdout_path.is_file(), f"Invalid stdout path: {stdout_path!r}"

    assert return_code is not None and isinstance(return_code, int), f"Invalid return code type: {type(return_code)}, {return_code!r}"


    with tempfile.TemporaryDirectory() as temp_dir:
        output_json_file = Path(temp_dir) / "output.json"

        cmd = [
            ORGANIZER_LIBS_DIR / "interpret_crash.sh",
            'libfuzzer',
            sanitizer.value,
            str(return_code),
            str(stderr_path),
            str(stdout_path),
            str(output_json_file),
        ]
        p = subprocess.run(cmd)
        return_code = p.returncode
        print(f"interpret_crash.sh ({cmd!r}) returned for sanitizer {sanitizer.value} with return code {return_code}")
        with open(output_json_file, "r", encoding="utf-8") as f:
            output_json = json.load(f)
            message = output_json.get("message", "No message found")
            significance = output_json.get("significance", return_code)  # Default to 1 if not found
            assert significance == return_code
            return message, SignificanceEnum(significance)

def interpret_crash(
    sanitizer: Union[str, SanitizerEnum],
    return_code: int,
    stderr: bytes,
    stdout: bytes,
) -> tuple[str, SignificanceEnum]:
    if type(sanitizer) is str:
        sanitizer = SanitizerEnum(sanitizer)
    with tempfile.NamedTemporaryFile() as stderr_file, tempfile.NamedTemporaryFile() as stdout_file:
        stderr_file.write(stderr)
        stdout_file.write(stdout)
        stderr_file.flush()
        stdout_file.flush()
        stderr_path = Path(stderr_file.name)
        stdout_path = Path(stdout_file.name)
        code_label, significance = interpret_crash_files(
            sanitizer,
            return_code,
            stderr_path,
            stdout_path,
        )
        return code_label, significance

def get_crash_state(
        stdout_bytes: bytes,
        stderr_bytes: bytes,
    ) -> tuple[str, Optional[str]]:
    """
    Get the crash state from the standard output and error bytes.
    Args:
        stdall_bytes (bytes): The combined standard output and error bytes.

    """

    crash_state = None
    instrumentation_key = None
    with tempfile.TemporaryDirectory() as temp_dir:
        input_file = Path(temp_dir) / "input.txt"
        stdall_bytes = stdout_bytes + b'\n' + stderr_bytes
        input_file.write_bytes(stdall_bytes)
        output_json_file = Path(temp_dir) / "output.json"
        p = subprocess.check_call([
            ORGANIZER_LIBS_DIR / "generate_crash_state.sh",
            str(input_file),
            str(output_json_file),
        ])
        with open(output_json_file, "r", encoding="utf-8") as f:
            output_json = json.load(f)
            crash_state = output_json.get("crash_state")
            instrumentation_key = output_json.get("instrumentation_key")
            assert isinstance(crash_state, str) or crash_state is None, f"Invalid crash state type: {type(crash_state)}, {crash_state!r}"
            assert isinstance(instrumentation_key, str) or instrumentation_key is None, f"Invalid instrumentation key type: {type(instrumentation_key)}, {instrumentation_key!r}"
    return crash_state, instrumentation_key or None

# Runs both get_crash_state and interpret_crash_files to return an OrganizerCrashEvaluation object.
def organizer_evaluate_crash(
        sanitizer: Union[str, SanitizerEnum],
        return_code: int,
        stdout_bytes: bytes,
        stderr_bytes: bytes,
        stdall_bytes: Optional[bytes] = None,
        unexpected_crash: Optional[bool] = None, # will be auto-computed from significance if needed
    ) -> OrganizerCrashEvaluation:
    """
    Evaluate the crash and return an OrganizerCrashEvaluation object.
    Args:
        stdall_bytes (bytes): The combined standard output and error bytes.
        sanitizer (SanitizerEnum): The sanitizer used.
    Returns:
        OrganizerCrashEvaluation: The evaluation result.
    """
    if stdall_bytes is None:
        stdall_bytes = stdout_bytes + b'\n' + stderr_bytes
    if type(sanitizer) is str:
        sanitizer = SanitizerEnum(sanitizer)

    code_label, significance = interpret_crash(
        sanitizer=sanitizer,
        return_code=return_code,
        stderr=stderr_bytes,
        stdout=stdout_bytes,
    )
    crash_state, instrumentation_key = get_crash_state(
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )

    return OrganizerCrashEvaluation(
        code_label=code_label,
        significance=SignificanceEnum(significance),
        significance_message=SignificanceEnum(significance).name,
        crash_state=crash_state,
        instrumentation_key=instrumentation_key,
    )

def get_is_organizer_duplicate(
        organizer_eval: dict,
        existing_evals: List[dict],
    ) -> List[bool]:
    """
    Check if the given organizer evaluation is a duplicate of any existing evaluations.
    Args:
        organizer_eval (dict of crash_state and instrumentation_key): The evaluation to check.
        existing_evals (List[dicts of crash_state and instrumentation_key]): The list of existing evaluations to compare against
    Returns:
        bool: True if the evaluation is a duplicate, False otherwise.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        with open(Path(temp_dir) / "input.json", "w", encoding="utf-8") as f:
            json.dump({
                'to_find': dict(crash_state=organizer_eval['crash_state'], instrumentation_key=organizer_eval['instrumentation_key']),
                'to_compare': [
                    dict(crash_state=existing_eval['crash_state'], instrumentation_key=existing_eval['instrumentation_key'])
                    for existing_eval in existing_evals
                ]
            }, f, indent=2, ensure_ascii=False)
        subprocess.check_call([
            str(ORGANIZER_LIBS_DIR / "deduplicate_crash_states.py"),
            str(Path(temp_dir) / "input.json"),
            str(Path(temp_dir) / "output.json"),
        ], cwd=ORGANIZER_LIBS_DIR)

        with open(Path(temp_dir) / "output.json", "r", encoding="utf-8") as f:
            return json.load(f)
        
def get_organizer_eval_duplicate_positions(
        organizer_eval: dict,
        existing_evals: List[dict],
    ) -> List[int]:
    """
    Return the duplicate entries in the existing_evals for the given organizer evaluation.
    Args:
        organizer_eval (dict of crash_state and instrumentation_key): The evaluation to check.
        existing_evals (List[dicts of crash_state and instrumentation_key]): The list of existing evaluations to compare against
    Returns:
        List[dict]: A list of duplicate evaluations found in existing_evals.
    """
    return [i for i, dup in enumerate(get_is_organizer_duplicate(
        organizer_eval=organizer_eval,
        existing_evals=existing_evals,
    )) if dup]

def get_organizer_eval_duplicates(
        organizer_eval: dict,
        existing_evals: List[dict],
    ) -> List[dict]:
    """
    Return the duplicate entries in the existing_evals for the given organizer evaluation.
    Args:
        organizer_eval (dict of crash_state and instrumentation_key): The evaluation to check.
        existing_evals (List[dicts of crash_state and instrumentation_key]): The list of existing evaluations to compare against
    Returns:
        List[dict]: A list of duplicate evaluations found in existing_evals.
    """
    
    is_duplicate_list = get_is_organizer_duplicate(
        organizer_eval=organizer_eval,
        existing_evals=existing_evals,
    )
    return [
        x for dup, x in zip(is_duplicate_list, existing_evals) if dup
    ]
