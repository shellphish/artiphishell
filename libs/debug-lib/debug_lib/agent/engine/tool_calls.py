import pprint
import logging
import re
import subprocess

from pathlib import Path
from typing import Dict, Any, List, Literal

import yaml


from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.models.crs_reports import RootCauseReport

from agentlib import tools

from debug_lib.agent.engine import debug_helper, utils
from debug_lib.debuggers import JDBDebugger, GDBDebugger
from crs_telemetry.utils import get_otel_tracer, get_current_span

log = logging.getLogger("dyva_tools")
tracer = get_otel_tracer()


@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.get_file_contents")
def get_file_contents(file_path: str, start_line: int = 0, end_line: int = -1) -> str:
    """
    This function retrieves the contents of a source file.
    Use the start_line and end_line parameters to retrieve a specific range of lines if the contents are too long.

    param file_path: str, the path to the source file to retrieve the contents from.
    param start_line: int, the start line to retrieve the contents from (OPTIONAL).
    param end_line: int, the end line to retrieve the contents until (OPTIONAL).

    return str, the contents of the source file.
    """
    return _get_file_contents_from_path(file_path, start_line, end_line)


def _get_file_contents_from_path(file_path: str, start_line: int = 0, end_line: int = -1) -> str:
    source_file = Path(file_path)
    if start_line != 0:
        start_line -= 1

    potential_functions: list[str] = list(debug_helper.FUNCTION_RESOLVER.find_by_filename(str(source_file)))
    code = ""
    prev_line = 1
    for function_info in sorted([debug_helper.FUNCTION_RESOLVER.get(x) for x in potential_functions], key=lambda x: x.start_line):
        code += "\n" * (function_info.start_line - prev_line)
        code += function_info.code
        prev_line = function_info.end_line

    if not code:
        return f"File {file_path} does not exist"

    if len(code) < start_line or len(code) < end_line:
        return f"You are trying to access lines that are out of range. The file has only {len(code)} lines."

    return utils.add_line_numbers_to_code(code, start_line, end_line, seek=True)

@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.get_similar_function_signatures")
def get_similar_function_signatures(function_name: str) -> List[str]:
    """
    This function is useful when you are having a difficult time finding the function signature you are looking for.
    This function retrieves the most similar function signatures to the given function name.
    param function_name: str, the function name to retrieve similar signatures for.

    return List[str], the list of most similar function signatures.
    """
    if not function_name:
        return "No function signature provided"

    # Use regex to extract the function name and arguments
    similar_signatures = debug_helper.FUNCTION_RESOLVER.find_by_funcname(function_name)
    return f"# SIMILAR FUNCTION SIGNATURES\nThe most similar function signatures to `{function_name}` are:\n```\n" + '\n'.join(f"{x.name} - {x.unique_identifier}" for x in similar_signatures) + "\n```"

@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.get_function_source")
def get_function_source(
    function_signature: str, file_path: str = None, reference_line_number: int = None, end_line_number: int = None
) -> str:
    """
    This function retrieves the source code for the specified function from the source file.
    param function_signature: str, the signature of the function to retrieve the source code for.
    param file_path: str, the path to the source file to retrieve the source code from.
    param reference_line_number: int, a line number in the function whose source you want to retrieve.
    param end_line_number: int, the maximum line number to retrieve the source code until.

    return str, the source code for the function or list of most similar signatures.
    """
    if file_path:
        file_path = file_path.replace(str(debug_helper.DYVA_STATE.oss_fuzz_project.project_source), "").lstrip("/")
        file_path = Path(file_path)

    function_info: FunctionIndex | Dict[str, str] = utils.get_function_source(
        function_signature,
        file_path,
        reference_line_number,
    )

    span = get_current_span()
    span.set_attribute("crs.action.code.file", str(file_path))
    if isinstance(function_info, dict):
        return function_info["error"]

    span.set_attribute("crs.action.code.lines", f"{function_info.start_line}-{function_info.end_line}")
    if not function_info.code:
        log.error("Crashing function source code is empty: %s", function_info)
        return f"Crashing function source code is empty: {function_info}"

    code_with_lines = utils.add_line_numbers_to_code(
        function_info.code, function_info.start_line, end_line_number or function_info.end_line
    )
    if function_info.funcname.lower() not in function_signature.lower():
        return f"There is no function we can find with the signature {function_signature}. Try to use the function name instead of the signature."

    return code_with_lines


# @tools.tool
# @tracer.start_as_current_span("debug_lib.tool_call.run_arbitrary_gdb_commands")
# def run_arbitrary_gdb_commands(commands: List[str]) -> List[Dict[str, Any]]:
#     """
#     Run an arbitrary gdb command
#     You will need to provide continue commands to continue the program after the gdb commands are run
#     Call the "run" command to start the program (only do this after setting breakpoints)

#     param commands: List[str], the list of gdb commands to run

#     return List[Dict[str, Any]], the output of the gdb commands
#     """
#     return gdb_helper.run_gdb_commands(commands, gdb_helper.DYVA_STATE.binary_path, gdb_helper.DYVA_STATE.input_data, gdb_helper.DYVA_STATE.gdb_remote)


@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.get_context_and_registers_at_lines")
def get_context_at_lines(lines: List[int], src_file: str, classpath: str = None) -> str:
    """
    Retrieves context, local variables, and register information for each line in the list (Maximum of 5 lines allowed).
    param lines: List[int], the line numbers to get the context and registers for
    param src_file: str, the source file to get the context and registers for
    param classpath: Optional[str], the classpath to use for the source file (NECESSARY FOR JAVA) e.g. com.example.YourClass
    You must provide the full classpath including the package name if you are using java.
    In Java the src_file name stem must also match the classpath

    return str, the context, local variables, and register information for each line in the list

    Note: The max amount of lines is 5.
    """
    break_lines = [int(line) for line in lines]
    if len(break_lines) == 0:
        return "get_function_source needs at least one line to break at"

    if len(break_lines) > 5:
        return f"get_context_at_lines needs at most 5 lines to break at. You provided {len(break_lines)} lines."

    real_file = debug_helper.DYVA_STATE.oss_fuzz_project.artifacts_dir / src_file.lstrip("/")
    src_file = Path(src_file)
    if not real_file.exists():
        for idx in range(len(src_file.parts) - 1):
            new_file = Path(*src_file.parts[idx:])
            for file in debug_helper.DYVA_STATE.oss_fuzz_project.artifacts_dir.rglob(f"*{new_file}"):
                real_file = file
                break
            if real_file.exists():
                break

    log.info("Getting context and registers at lines %s", break_lines)
    span = get_current_span()
    span.set_attribute("crs.action.code.file", str(real_file))
    span.set_attribute("crs.action.code.lines", f"{','.join(map(str, break_lines))}")
    with debug_helper.get_new_debugger_from_dyva() as debugger:
        if isinstance(debugger, JDBDebugger) and not classpath:
            raise ValueError("Classpath is required for Java debugging")

        trace = debug_helper.get_context_and_registers_between_lines(
            debugger,
            break_lines,
            real_file,
            classpath=classpath,
        )
    log.info("Trace: %s", trace)
    return pprint.pformat(trace, indent=2)

def _find_matching_signature_from_location_of_interest(loc: dict):
    signatures = resolve_function_name(loc["function"], error=False)
    if isinstance(signatures, list):
        for signature in signatures:
            try:
                line_no = int(signature.split(":")[1])
            except ValueError:
                line_no = None

            if loc['function'] in signature and loc['file'] in signature and loc['start_line'] >= line_no:
                break
        else:
            raise ValueError(f"No matching signature found for {loc}, here are some similar signatures:{pprint.pformat(signatures, indent=2)}")
    else:
        signature = signatures
    return signature

@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.propose_root_cause")
def propose_root_cause(yaml_report: str) -> str:
    """
    Propose a root cause for the crash and write it to the output file.
    param yaml_report: str, yaml report with specific structure
    """
    log.info("Proposing root cause: \n%s", yaml_report)
    try:
        yaml_report = yaml.safe_load(yaml_report)
        yaml_report["found_root_cause"] = True
        RootCauseReport.model_validate(yaml_report)
        for idx, bug in enumerate(yaml_report["bug_locations"].copy()):
            signature = _find_matching_signature_from_location_of_interest(bug)
            yaml_report["bug_locations"][idx]["signature"] = signature
        for idx, rcl in enumerate(yaml_report["root_cause_locations"].copy()):
            signature = _find_matching_signature_from_location_of_interest(rcl)
            yaml_report["root_cause_locations"][idx]["signature"] = signature
        debug_helper.DYVA_STATE.root_cause_report = RootCauseReport.model_validate(yaml_report)
        debug_helper.DYVA_STATE.found_root_cause = True
        if debug_helper.DYVA_STATE.output_path:
            debug_helper.DYVA_STATE.output_path.write_text(yaml.dump(yaml_report))
    except Exception as e:
        log.error("Error validating root cause: %s", e, exc_info=True)
        return f"Error validating root cause: {e}"

    return "Root cause was proposed and successfully written to the output path"


@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.set_breakpoint_and_run_commands")
def set_breakpoint_and_run_commands(
    src_file: str = None,
    line_number: int = None,
    function_signature: str = None,
    function_name: str = None,
    commands: List[str] = None,
) -> str:
    """
    Sets a breakpoint at the specified line number in the source code.
    Runs arbitrary gdb commands at the breakpoint.
    NOTE: You can only provide a combination of the following parameters:
          (src_file, line_number, function_signature) or (function_name)
          Providing src_file, line_number, and function_signature is strongly preferred.

    :param src_file: The name of the source file to analyze.
    :param line_number: The line number in the src_file to break at.
    :param function_signature: The signature of the function to break inside of.

    :param function_name: The name of the function to break inside of.

    :param commands: The list of gdb commands to run at the breakpoint.
    :return: A dictionary containing the output of the gdb commands with the key being the command.

    Call this function only after you have seen the source code of the function_signature
    """

    if (not src_file or not line_number or not function_signature) and not function_name:
        if any([src_file, line_number, function_signature]):
            assert False, (
                f"At least one of src_file, line_number, or function_signature must be provided."
                f" Given: {src_file=}, {line_number=}, {function_signature=}"
            )
        else:
            assert False, "At least one of src_file, line_number, or function_signature must be provided"

    if src_file and line_number:
        src_file_path = debug_helper.DYVA_STATE.oss_fuzz_project.artifacts_dir / str(src_file).lstrip("/")
        function_info: FunctionIndex | None = utils.get_function_info_from_signature(
            function_signature,
            debug_helper.DYVA_STATE.function_json_path,
            debug_helper.DYVA_STATE.function_indices_path,
            src_file.replace(str(debug_helper.DYVA_STATE.oss_fuzz_project.source_repo_path), "").lstrip("/"),
            line_number,
        )
        if function_info is None:
            message = f"Here are some similar function signatures:\n {pprint.pformat(function_info, indent=2)}\n\n"
            """
                We provide error message such that LLM can understand the error, and also try to correct it.
                A good way to do that is to provide how we generate the source file path
            """
            error_message = f"""
    Error: The source file path is generated as follows: os.path.join(SRC_ROOT_PATH, src_file_name).
    Current output was: {src_file_path}, which does not exist. Please provide the correct source file path.

    {message}
    """
            log.error(error_message)
            return error_message
        with debug_helper.get_new_debugger_from_dyva() as debugger:
            output_commands = debug_helper.get_info_at_location(
                debugger=debugger,
                src_name=src_file,
                line_number=line_number,
                commands=commands,
            )

    else:
        with debug_helper.get_new_debugger_from_dyva() as debugger:        
            output_commands = debug_helper.get_info_at_location(
                debugger=debugger,
                function_name=function_name,
                commands=commands,
            )

    output_str = ""
    for command, output in output_commands.items():
        output_str += f"{command}:\n{output}\n\n"

    return output_str


@tools.tool
@tracer.start_as_current_span("debug_lib.tool_call.set_breakpoint_and_get_context")
def set_breakpoint_and_get_context(
    src_file: str = None, line_number: int = None, function_signature: str = None, function_name: str = None
) -> str:
    """
    Sets a breakpoint at the specified line number in the source code.
    Retrieves the context and registers at that breakpoint.
    NOTE: You can only provide a combination of the following parameters:
          (src_file, line_number, function_signature) or (function_name)
          Providing src_file, line_number, and function_signature is strongly preferred.

    :param src_file: The name of the source file to analyze.
    :param line_number: The line number in the src_file to break at.
    :param function_signature: The signature of the function to break inside of.

    :param function_name: The name of the function to break inside of.

    :return: A dictionary containing context information at the breakpoint.

    Call this function only after you have seen the source code of the function_signature
    """

    if (not src_file or not line_number or not function_signature) and not function_name:
        if any([src_file, line_number, function_signature]):
            assert False, (
                f"At least one of src_file, line_number, or function_signature must be provided."
                f" Given: {src_file=}, {line_number=}, {function_signature=}"
            )
        else:
            assert False, "At least one of src_file, line_number, or function_signature must be provided"

    if src_file and line_number:
        src_file_path = debug_helper.DYVA_STATE.oss_fuzz_project.artifacts_dir / str(src_file).lstrip("/")
        function_info: FunctionIndex | None = utils.get_function_info_from_signature(
            function_signature,
            debug_helper.DYVA_STATE.function_json_path,
            debug_helper.DYVA_STATE.function_indices_path,
            src_file.replace(str(debug_helper.DYVA_STATE.oss_fuzz_project.project_source), "").lstrip("/"),
            line_number,
        )
        if function_info is None:
            message = f"Here are some similar function signatures:\n {pprint.pformat(function_info, indent=2)}\n\n"
            """
                We provide error message such that LLM can understand the error, and also try to correct it.
                A good way to do that is to provide how we generate the source file path
            """
            error_message = f"""
    Error: The source file path is generated as follows: os.path.join(SRC_ROOT_PATH, src_file_name).
    Current output was: {src_file_path}, which does not exist. Please provide the correct source file path.

    {message}
    """
            log.error(error_message)
            return error_message
        span = get_current_span()
        span.set_attribute("crs.action.code.file", str(src_file_path))
        span.set_attribute("crs.action.code.lines", f"{line_number}")
        with debug_helper.get_new_debugger_from_dyva() as debugger:
            _, trace_str = debug_helper.get_info_at_location(
                debugger=debugger,
                src_name=src_file if isinstance(debugger, GDBDebugger) else function_info.class_name,
                line_number=line_number,
            )
    else:
        with debug_helper.get_new_debugger_from_dyva() as debugger:
            _, trace_str = debug_helper.get_info_at_location(
                debugger=debugger,
                function_name=function_name,
            )

    return trace_str

@tools.tool
def get_functions_in_file(file: str) -> List[str]:
    """
    Return a list of functions in the file `file`..

    The `file` must be relative to the `/src/` directory and must exist in the target sources.
    If the file does not exist, a ValueError will be raised.
    Args:
        file (str): The relative path of the file (relative to `/src/`). This does not support directories.
    Returns:
        List[str]: A list of functions in the file.
    """
    try:
        if file.startswith('oss-fuzz:'):
            file = file[len('oss-fuzz:'):]
        elif file.startswith('source:'):
            file = file[len('source:'):]

        functions = debug_helper.FUNCTION_RESOLVER.find_by_filename(file)
        log.info('[LLM-TOOL-CALL: get_functions_in_file] Resolved functions in file %r to %r', file, functions)
        return f'# FUNCTIONS IN FILE\nThe functions found in `{file}` are:\n```\n' + '\n'.join(functions) + '\n```'
    except Exception as e:
        log.warning(f"Failed to get functions in file: {file}", exc_info=True)
        raise ValueError(f"ERROR: Failed to get functions in file: {file}. Error: {e}")

@tools.tool
def find_function(function_name: str) -> tuple[str, str]:
    """
    Return information about the function named `name`. Includes metadata as well as the source code if found.
    If you already have a fully specifified name, always use that to avoid ambiguity.
    """
    try:
        key = resolve_function_name(function_name)
        entry = debug_helper.FUNCTION_RESOLVER.get(key)
        return f'''
# {entry.target_container_path}:{entry.start_line} for {key}
<code>
{entry.code}
</code>
'''
    except Exception as e:
        log.warning(f"Failed to find function: {function_name}", exc_info=True)
        raise ValueError(f"ERROR: Failed to find function: {function_name}. Error: {e}")


def resolve_function_name(name: str, error=True) -> str:
    """
    Resolve the function name to a fully qualified name.
    This is useful for resolving the file location, line number, and code from a function name.
    Multiple function names may be returned if there are several close matches.
    Args:
        name (str): The name of the function to resolve.
    """
    funcs = list(debug_helper.FUNCTION_RESOLVER.resolve_with_leniency(name))
    if len(funcs) > 1:
        all_func_hashes = set()
        last_directly_compiled = None
        for func_key in funcs:
            func = debug_helper.FUNCTION_RESOLVER.get(func_key)
            all_func_hashes.add(func.hash)

            if func.was_directly_compiled:
                last_directly_compiled = func_key

        if len(all_func_hashes) == 1:
            # okay, all functions are really the same, but they have likely just been copied before compiling
            # just return the first but prefer ones that were directly compiled as they are what will be appearing
            # in the coverage reports
            return last_directly_compiled if last_directly_compiled else funcs[0]

    
        if error:
            raise ValueError(f"Found multiple distinct functions with name {name}. Please be more specific. Options for fully specified names are: {funcs}")
        else:
            return funcs
    elif len(funcs) == 1:
        return funcs[0]
    else:
        raise ValueError(f"Could not find any function matching {name}.")

@tools.tool
def src_search(regex: str) -> str:
    """
    Search source files for a matching line to the provided regex.
    The regex is passed to the grep command, which will search all files in the source directory.
    return the first 50 found matches as a grep result.
    if the results are truncated, a message will be added to the output. (You may want to try a more specific query if this happens)
    i.e.
        file.c:38:         if (condition) {
        src/file2.c:38:    condition && other_condition
    """
    source_dir = debug_helper.DYVA_STATE.oss_fuzz_project.project_source
    grep_results = subprocess.run(["grep", "-rnE", regex, str(source_dir)], text=True, capture_output=True)
    output = ""
    for idx, res in enumerate(grep_results.stdout.strip().split("\n")):
        if idx > 49:
            output += f"Too many results, only showing first 50, maybe try a more specific query\n"
            break

        if not res or res.startswith("grep:"):
            continue
        path, line = res.split(":", 1)
        if len(line) > 100:
            line = line[:100] + "(... truncated ...)"
        path = Path(path).relative_to(source_dir)
        output += f"{path}:{line}\n"
    return output


AVAILABLE_TOOLS = [
    get_function_source,
    get_file_contents,
    get_similar_function_signatures,
    get_context_at_lines,
    set_breakpoint_and_get_context,
    get_functions_in_file,
    find_function,
    src_search,
    # set_breakpoint_and_run_commands,
    # run_arbitrary_gdb_commands,
    propose_root_cause,
]
