import os
import re
import random
from pathlib import Path
from loguru import logger
from typing import Tuple

from agentlib import Agent
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.indexer import FunctionIndex

from .agents import (
    AIJONInstrumentorAgent,
    AIJONJavaInstrumentorAgent,
    AIJONFixerAgent,
    AIJONCritiqueAgent,
)

PATCH_ID = 0


def apply_llm_response(
    original_code: str, llm_response: str, language: str, line_offset: int = 0
) -> Tuple[str, list[str], int]:
    global PATCH_ID
    failed_blocks = []
    success_blocks = 0
    changes = parse_llm_edits(llm_response, language)

    original_lines = original_code.split("\n")
    # logger.debug(f"Applying on: {original_code=}")

    for change_line_number, change_content in changes:
        change_line_number += line_offset
        if change_line_number == len(original_lines):
            logger.warning("Warning: refusing to insert after the last line.")
            continue

        try:
            prev_line = next(original_lines[n] for n in range(change_line_number, 0, -1) if original_lines[n])
            next_line = next(
                original_lines[n] for n in range(change_line_number + 1, len(original_lines)) if original_lines[n]
            )
        except StopIteration:
            logger.warning("Warning: refusing to insert at the start or end of the file.")
            continue
        prev_line = re.sub(r"/\*.*\*/", "", re.sub(r"//.*$", "", prev_line)).strip()
        if not prev_line or not (prev_line[-1] in ";{}" or ("case" in prev_line and prev_line.endswith(":"))):
            logger.warning(f"Warning: refusing to follow dangerous line: {prev_line}")
            continue
        if re.search(r"(^|[^A-Za-z0-9])for[^A-Za-z0-9].*;$", prev_line):
            logger.warning(f"Warning: refusing to follow start of multi-line for: {prev_line}")
            continue

        next_line = re.sub(r"/\*.*\*/", "", re.sub(r"//.*$", "", next_line)).strip()
        if next_line.startswith("else"):
            logger.warning(f"Warning: refusing to insert between uncurled if and else: {next_line}")
            continue

        if "#" in prev_line:
            logger.warning(f"Warning: refusing to insert after unpredictable preprocessor code: {prev_line}")
            continue
        if "#" in next_line:
            logger.warning(f"Warning: refusing to insert before unpredictable preprocessor code: {next_line}")
            continue

        PATCH_ID += random.randrange(1, 1024)
        actual_content = change_content.strip(";") + f"; /* PATCHID:{PATCH_ID} */"
        original_lines.insert(change_line_number + 1, actual_content)
        success_blocks += 1

    logger.debug(f"Applied {success_blocks=} of {len(changes)=} changes")
    return "\n".join(original_lines), failed_blocks, success_blocks


def get_agent_cost(agent: Agent):
    return sum((usage.get_costs(model)["total_cost"] for model, usage in agent.token_usage.items()))


def line_enumerated(code: str) -> list[str]:
    return "\n".join(f"{n}: {s}" for n, s in enumerate(code.split("\n")))


def instrument_code_with_ijon(
    poi: dict,
    function_index: FunctionIndex,
    modified_source_dir: Path,
    retry_limit: int = 3,
    write_out: bool = False,
    language: str = None,
) -> tuple[float, str]:
    """
    Instrument the given code using the AIJON instrumentor agent.

    Args:
        poi (dict): The Point of Interest (POI) describing the vulnerability.
        function_index (FunctionIndex): The FunctionIndex for the function that was mentioned in the POI.
        modified_source_dir (Path): The directory where the modified source code will be saved.
    """

    cost = 0.0
    # Objectives:
    # 1. Use the POI to insert a IJON vulnerability constraint into the function_index function.

    func_code = function_index.code
    target_file_path = modified_source_dir / function_index.focus_repo_relative_path

    if not target_file_path.is_file():
        logger.warning(f"Target file {target_file_path} does not exist.")
        # This will be caught by the worker
        raise ValueError(f"Target file {target_file_path} does not exist.")

    # Add the IJON constraint to the function_index function
    language: str = language or os.getenv("LANGUAGE")
    if language == LanguageEnum.jvm.value:
        instrumentor_agent = AIJONJavaInstrumentorAgent()
    elif language in [LanguageEnum.c.value, LanguageEnum.cpp.value]:
        instrumentor_agent = AIJONInstrumentorAgent()
    else:
        raise NotImplementedError(f"Not implemented for language {language}")

    retry = None
    curly_braces = None
    for _ in range(retry_limit):
        response = instrumentor_agent.invoke(
            {
                "code": line_enumerated(func_code),
                "poi_report": poi,
                "retry": retry,
                "curly_braces": curly_braces,
            }
        )
        cost += get_agent_cost(instrumentor_agent)

        logger.trace(f"Response from LLM 🤖: {response.value}")
        logger.debug(f"Cost of instrumentor agent: {cost}")
        failed = False
        if not is_valid_response(response.value, language):
            logger.warning("LLM response is not valid. Response:\n" + response.value)
            retry = True
            continue
        else:
            try:
                instrumented_code, failed_blocks, num_success = apply_llm_response(
                    original_code=func_code, llm_response=response.value, language=language
                )
                try:
                    critique_agent = AIJONCritiqueAgent(language=language)
                    critique_response = critique_agent.invoke(
                        {
                            "function_source": line_enumerated(func_code),
                            "diff": response.value,
                            "failed_blocks": "\n".join(failed_blocks),
                            "has_failed": bool(failed_blocks),
                            "compiler_error": None,
                        }
                    )
                    critique_cost = get_agent_cost(critique_agent)
                    logger.debug(f"Critique response: {critique_response.value}")
                    logger.debug(f"Cost of critique agent: {critique_cost}")
                    cost += critique_cost
                    if not is_valid_response(critique_response.value, language):
                        logger.warning("Critique LLM response is not valid. Response:\n" + critique_response.value)
                        failed = True
                    else:
                        instrumented_code, failed_blocks, num_success = apply_llm_response(
                            original_code=func_code,
                            llm_response=critique_response.value,
                            language=language,
                        )
                        response = critique_response

                except Exception as e:
                    logger.warning(f"Critique agent failed: {e}")

            except AssertionError:
                logger.warning("Search block was empty.")
                failed = True
            except ValueError:
                logger.warning("Original code not found in the provided code.")
                failed = True

        if not failed:
            break

        logger.warning("LLM response is not valid.")
        retry = True
    else:
        if not is_valid_response(response.value, language) or failed:
            raise ValueError("LLM was unable to instrument code. Response:\n\n" + response.value)

    if write_out:
        target_file_path.write_text(instrumented_code)
        logger.success(f"Instrumented code written to {target_file_path}")

    return cost, response.value


def parse_llm_edits(response: str, language: str) -> list[tuple[str, int, str]]:
    changes = []
    for line in response.split("RESULT", 1)[1].split("\n"):
        if not line:
            continue
        parts = line.split(" ", 2)
        if not len(parts) == 3:
            logger.warning(f"Invalid line {parts}: length is not 3.")
            continue
        if parts[0] != "+":
            logger.warning(f"Invalid line {parts}: malformed first character.")
            continue
        try:
            line_no = int(parts[1])
        except ValueError:
            logger.warning(f"Invalid line {parts}: cannot convert {parts[1]} to number.")
            continue
        if not parts[2].startswith("IJON"):
            logger.warning(f"Invalid line {parts}: Missing IJON instrumentation.")
            continue
        if re.search(r"[A-Za-z0-9_]\(", parts[2].split("(", 1)[1].replace("sizeof", "")):
            if language != LanguageEnum.jvm.value:
                logger.warning(f"Invalid line {parts}: function call.")
                continue
        if "(void)" in parts[2]:
            logger.warning(f"Invalid line {parts}: void cast.")
            continue
        # stupid LLM keeps adding comments
        # if not parts[2].endswith(")") and not parts[2].endswith(";"):
        #   logger.warning("Invalid line {parts}: malformed last character.")
        #   continue

        if language == LanguageEnum.jvm.value:
            method, args = parts[2].strip(";").split("(")
            args = args[:-1]
            annotation = f"""try {{ Class.forName("IJONJava") .getMethod("{method}", int.class) .invoke(null, {args}); }} catch (Exception e) {{ e.printStackTrace(); }}"""
        else:
            annotation = parts[2]

        changes.append((line_no, annotation))

    return sorted(changes, key=lambda x: -x[0])


def is_valid_response(response: str, language: str) -> bool:
    """
    Makes sure that the response from the LLM contains at least one line replacement or insertion.
    """
    if "RESULT" not in response:
        logger.warning("Invalid response: no RESULT found.")
        return False

    changes = parse_llm_edits(response, language)
    if changes:
        return True

    logger.warning("Invalid response: no valid edits.")
    return False


def is_valid_deletion_response(response: str) -> bool:
    """
    Makes sure that the response from the LLM contains at least one line replacement or insertion.
    """
    if "RESULT" not in response:
        logger.warning("Invalid response: no RESULT found.")
        return False

    changes = parse_llm_deletions(response)
    if changes:
        return True

    logger.warning("Invalid response: no valid edits.")
    return False


def parse_llm_deletions(response: str) -> list[int]:
    changes: list[int] = []
    for line in response.split("RESULT", 1)[1].split("\n"):
        if not line:
            continue
        parts = line.split(" ", 2)
        if not len(parts) == 3:
            logger.warning(f"Invalid line {parts}: length is not 3.")
            continue
        if parts[0] not in "+%-":
            logger.warning(f"Invalid line {parts}: malformed first character.")
            continue
        if parts[1] != "PATCHID":
            logger.warning(f"Invalid line {parts}: PATCHID not found.")
            continue
        try:
            patch_id = int(parts[2])
        except ValueError:
            logger.warning(f"Invalid line {parts}: cannot convert {parts[2]} to number.")
            continue
        changes.append(patch_id)

    return sorted(changes)


def find_error_locations(
    compiler_error_str: str,
    applied_diff: str,
    retry_limit: int = 3,
) -> list[int]:
    cost = 0.0
    fixer_agent = AIJONFixerAgent()
    bad_block = None
    retry = None
    failed_blocks = []
    location_infos = []

    logger.debug("Finding error locations in the applied diff.")
    for _ in range(retry_limit):
        response = fixer_agent.invoke(
            {
                "applied_diff": applied_diff,
                "compiler_error": compiler_error_str,
                "retry": retry,
                "bad_block": bad_block,
                "failed_blocks": "\n".join(failed_blocks),
                "has_failed": bool(failed_blocks),
            }
        )
        cost += get_agent_cost(fixer_agent)
        logger.debug(f"Cost of fixer agent: {cost}")

        if not is_valid_deletion_response(response.value):
            logger.warning("LLM response is not valid.")
            bad_block = True
            retry = None
            continue
        else:
            logger.debug(f"Response from LLM 🤖: {response.value}")
            logger.info("Parsing LLM response for deletion locations.")
            try:
                location_infos = parse_llm_deletions(response.value)
                break
            except Exception:
                logger.warning("Failed to parse LLM response for deletion locations.")
                location_infos = []

    logger.info(f"Found {len(location_infos)} error locations in the applied diff.")
    return location_infos
