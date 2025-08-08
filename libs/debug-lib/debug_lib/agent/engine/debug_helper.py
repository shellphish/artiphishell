import re
import time
import shutil
import os
import subprocess
import logging

from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Generator, Literal, Optional
from debug_lib.debuggers import GDBDebugger, JDBDebugger, Debugger
from collections import Counter
from pathlib import Path
from contextlib import contextmanager

from shellphish_crs_utils.function_resolver import FunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models import POIReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.crs_reports import RootCauseReport
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum

from debug_lib.debuggers.context import DebugContext

log = logging.getLogger(__name__)

DEBUGGER = None

FUNCTION_RESOLVER: FunctionResolver = None

@dataclass
class DyvaState:
    oss_fuzz_project: OSSFuzzProject
    poi_report: POIReport
    output_path: Path | None
    binary_path: Path
    input_data: Path
    found_root_cause: bool = False
    root_cause_report: RootCauseReport = None
    crash_report: Dict[str, Any] = None
    debug_remote: str = None
    arbitrary_crash: bool = False
    should_catch_exit: bool = False
    should_follow_child: bool = False
    class_name: str = None


# Global state
# I hate that this exists, but it's a necessary evil for langchain tool calling
# langchain removes the instance reference so `self` is not available

DYVA_STATE: DyvaState = None


def init_dyva_state(
    oss_fuzz_project: OSSFuzzProject,
    input_data: Path,
    poi_report: POIReport = None,
    function_resolver: Optional[FunctionResolver] = None,
    cp_name: str = None,
    project_id: str = None,
    output_path: Path = None,
    binary_path: Path = None,
    gdb_remote: str = None,
    arbitrary_crash: bool = False,
) -> DyvaState:
    """Initialize the global DYVA state"""
    global DYVA_STATE
    global FUNCTION_RESOLVER

    if function_resolver is not None:
        FUNCTION_RESOLVER = function_resolver
    else:
        FUNCTION_RESOLVER = RemoteFunctionResolver(cp_name=cp_name, project_id=project_id)

    bin_path = binary_path or (oss_fuzz_project.artifacts_dir / poi_report.cp_harness_binary_path)
    DYVA_STATE = DyvaState(
        oss_fuzz_project=oss_fuzz_project,
        poi_report=poi_report,
        output_path=output_path,
        binary_path=bin_path,
        debug_remote=gdb_remote,
        arbitrary_crash=arbitrary_crash,
        input_data=input_data,
    )

    return DYVA_STATE


def generate_report(all_states: list[DebugContext]) -> str:
    """
    Generates a detailed report from the collected all_states data, focusing only on changes.
    Ensures that the backtrace is included only once in the report.

    :param all_states: List of states collected at each breakpoint.
    :return: A formatted string report.
    """
    report = []
    previous_locals = {}

    for idx, context in enumerate(all_states):
        # Unpack the entry
        register_changes = [f"{reg.name}: {hex(reg.value)}" for reg in context.registers.values() if reg.changed]

        # Parse local variables
        current_locals = {var.name: var.value for var in context.locals}
        local_changes = []

        if idx == 0:
            # Initial state: list all local variables
            local_changes = [f"{var.name}: {var.type} {var.value}" for var in context.locals]
        else:
            # Compare with previous locals
            for var in context.locals:
                prev_val = previous_locals.get(var.name)
                if prev_val != var.value:
                    local_changes.append(f"{var.name}: {var.type} {prev_val} -> {var.value}")

        try:
            signatures = list(FUNCTION_RESOLVER.resolve_with_leniency(context.frame.function))
            if isinstance(signatures, list) and len(signatures) > 1:
                for signature in signatures:
                    try:
                        line_no = int(signature.split(":")[1])
                    except ValueError:
                        line_no = None

                    if context.frame.function in signature and context.frame.file.name in signature and context.frame.line >= line_no:
                        break
                else:
                    raise FileNotFoundError
                
            elif not signatures:
                raise FileNotFoundError
            else:
                signature = signatures[0]
            _, _, start_line, code = FUNCTION_RESOLVER.get_code(signature)
            source_code = code.splitlines()[context.frame.line - start_line]
        except (FileNotFoundError, ValueError):
            source_code = f"Could not get source code line for {context.frame.file} does not exist"
            log.error("Could not get source code %s does not exist", context.frame.file, exc_info=True)

        # Build the report section for the current entry
        section = f"\t<Breakpoint {idx + 1}>\n"
        section += f"\t\t<Function>{context.frame.function}</Function>\n"
        section += f"\t\t<Line Number>{context.frame.line}</Line Number>\n"
        section += f"\t\t<Source Line>{source_code}</Source Line>\n"
        if context.pc:
            section += f"\t\t<Program Counter>{hex(context.pc)}</Program Counter>\n"

        # Register Changes
        if register_changes:
            section += "\t\t"
            section += "<Register Changes>\n" if idx != 0 else "<Initial Register States>\n" 
            for reg in register_changes:
                section += f"\t\t\t- {reg}\n"
            section += "\t\t"
            section += "</Register Changes>\n" if idx != 0 else "</Initial Register States>\n"
        else:
            section += "\t\t"
            section += "<Register Changes></Register Changes>\n"

        # Local Variable Changes
        if idx == 0:
            if local_changes:
                section += "\t\t"
                section += "<Initial Local Variables>\n"
                for var in local_changes:
                    section += f"\t\t\t- {var}\n"
                section += "\t\t"
                section += "</Initial Local Variables>\n"
            else:
                section += "\t\t"
                section += "<Initial Local Variables></Initial Local Variables>\n"
        else:
            if local_changes:
                section += "\t\t"
                section += "<Local Variable Changes>\n"
                for var in local_changes:
                    section += f"\t\t\t- {var}\n"
                section += "\t\t"
                section += "</Local Variable Changes>\n"
            else:
                section += "\t\t"
                section += "<Local Variable Changes></Local Variable Changes>\n"

        backtrace_str = "\t\t<Backtrace>\n"
        backtrace_str += "\n\t\t\t".join(str(x) for x in context.backtrace.bt)
        backtrace_str += "\t\t</Backtrace>\n"
        section += backtrace_str
        section += f"\t</Breakpoint {idx + 1}>\n"
        report.append(section)

        # Update previous locals for next iteration
        previous_locals = current_locals

    # Combine all sections into the final report
    final_report = "\n".join(report)
    final_report = f"<Report>\n\n{final_report}\n\n</Report>"
    return final_report

def get_current_debugger() -> Debugger:
    """
    Returns the current debugger instance.
    """
    global DEBUGGER
    if DEBUGGER is None:
        raise ValueError("No debugger instance found. Please create a new debugger instance first.")
    return DEBUGGER

@contextmanager
def get_new_debugger_from_dyva() -> Generator[Debugger, None, None]:
    """
    Returns a new debugger instance based on the global DYVA state.
    """

    with get_new_debugger(
        binary_path=DYVA_STATE.binary_path,
        input_data=Path("/work/pov_input"),
        debugger_type="jdb" if DYVA_STATE.oss_fuzz_project.project_language == LanguageEnum.jvm else "gdb",
        class_name=DYVA_STATE.class_name,
        remote=DYVA_STATE.debug_remote,
    ) as debugger:
        if isinstance(debugger, GDBDebugger):
            if DYVA_STATE.should_follow_child:
                debugger.raw("set follow-fork-mode child")
            if DYVA_STATE.should_catch_exit:
                debugger.raw("set follow-exec-mode same")
                debugger.raw("catch syscall exit_group")

        yield debugger


@contextmanager
def get_new_debugger(binary_path: Path, input_data: Path, debugger_type: Literal["gdb", "jdb"], class_name: str = None, remote: str = None) -> Generator[GDBDebugger, None, None]:
    """
    param binary_path: Path - Path to the challenge binary file (not the harness)
    param input_file: Path - Path to the crashing input file
    param remote: Path - path to gdb run script
    """
    global DEBUGGER
    if DEBUGGER:
        DEBUGGER.quit()
        DEBUGGER = None

    if debugger_type == "gdb":
        if remote:
            debugger = GDBDebugger(binary_path, argv=[str(input_data)], remote=remote)
        else:
            debugger = GDBDebugger(
                binary_path,
                remote=remote,
                extra_args=["gdb", "--nx", "--quiet", "--interpreter=mi3", "--args", str(binary_path), str(input_data)],
            )
        debugger.raw("delete")  # Delete all breakpoints
    elif debugger_type == "jdb":
        out_path = DYVA_STATE.oss_fuzz_project.artifacts_dir / "out"
        all_java_class_paths = [Path("/out", x.relative_to(out_path)) for x in out_path.rglob("*.jar")] + [Path("/out")]

        source_path = DYVA_STATE.oss_fuzz_project.artifacts_dir_built_src
        all_java_source_paths = [Path("/src", x.relative_to(source_path).parent) for x in source_path.rglob("com")] + [Path("/src")]
        debugger = JDBDebugger(binary_path, argv=[str(input_data)], classpath=all_java_class_paths, source_path=all_java_source_paths, class_name=class_name, remote=remote)
    else:
        raise ValueError(f"Invalid debugger type {debugger_type}. Supported types are: gdb, jdb")
    try:
        DEBUGGER = debugger
        yield debugger
    finally:
        debugger.quit()
        DEBUGGER = None

# If this function exists why is there a need of get_local_variable_and_backtrace???
def get_context_and_registers_between_lines(
    debugger: Debugger,
    break_lines: List[int],
    src_path: Path,
    classpath: Path,
):
    """
    Retrieves the local variables, registers, and backtrace of the program
    for each instruction between the specified start and end lines.

    :param start_line: The starting line number of the code segment to analyze.
    :param end_line: The ending line number of the code segment to analyze.
    :param input_data: Path to the input file
    :param binary_path: Path to the binary file of the program.
    :param src_path: Path to the source file of the program.

    :return: A dictionary containing context and register information each instruction in the specified code segment.
    """
    # start_remote_debugger(Path(binary_path).parent, Path(binary_path).name, "harness")
    if len(break_lines) == 0:
        print("ERROR in get_context_and_registers_between_addresses: No breakpoints provided")
    log.info("Getting context and registers between lines %s and %s", break_lines[0], break_lines[-1])
    for line in break_lines:
        if isinstance(debugger, GDBDebugger):
            debugger.set_breakpoint(file=src_path.name, line=line)
        else:
            debugger.set_breakpoint(class_path=classpath, line=line)

    total_breakpoints = len(set([str(line) for line in debugger.breakpoints]))
    all_states: list[DebugContext] = []
    debugger.run()
    try:
        for _ in range(total_breakpoints):
            if debugger.exited:
                log.info("Debugger exited")
                break
            log.info("Running debugger")
            all_states.append(debugger.context.copy())
            debugger.continue_execution()
    except Exception as e:
        log.error("Error in stepping to next instruction: %s", e, exc_info=True)
    output_report = generate_report(all_states)
    return output_report

def get_info_at_location(
    debugger: Debugger,
    src_name: str = None,
    line_number: int = None,
    function_name: str = None,
    crash: bool = False,
    commands: List[str] = None,
):
    if isinstance(debugger, GDBDebugger):
        if src_name and line_number:
            debugger.set_breakpoint(file=src_name, line=line_number)
        elif function_name:
            debugger.set_breakpoint(function=function_name)
    elif isinstance(debugger, JDBDebugger):
        if src_name and line_number:
            debugger.set_breakpoint(class_path=src_name, line=line_number)
        elif src_name and function_name:
            debugger.set_breakpoint(class_path=src_name, line=line_number)
    elif not crash:
        raise ValueError("Either src_name and line_number or function_name must be provided")

    debugger.run()

    command_outputs = {}
    if isinstance(debugger, GDBDebugger):
        for command in commands or []:
            output = debugger.raw(command)
            output_str = ""
            for line in output:
                if line["type"] == "result":
                    break
                if line["type"] == "console":
                    output_str += f"{line['payload']}\n"
            command_outputs[command] = output_str
    elif commands:
        raise ValueError("Commands are not supported for JDBDebugger")

    if command_outputs:
        return command_outputs

    bt_level = None
    failed_to_break = False
    if function_name:
        if function_name not in debugger.backtrace[0].function_name:
            failed_to_break = True
            bt_level = next((idx for idx, bt in enumerate(debugger.backtrace) if function_name in bt.function_name), None)
    elif src_name and line_number:
        if debugger.backtrace[0].file.stem not in str(src_name) or debugger.backtrace[0].line != line_number:
            failed_to_break = True
            bt_level = next(
                (
                    idx
                    for idx, bt in enumerate(debugger.backtrace)
                    if bt.file.name in str(src_name) and bt.line == line_number
                ),
                None,
            )

    if bt_level is not None:
        debugger.up(bt_level)
    if failed_to_break and bt_level is None:
        start = None
        end = None
        for idx, bt in enumerate(debugger.backtrace):
            if start is None and "llvm" in str(bt.file).lower():
                start = idx
            elif start is not None and "llvm" not in str(bt.file).lower():
                end = idx
                start = None

            if start is not None and end is not None:
                log.info("Attempting to change frame to the end of the valid context")
                debugger.up(end)
                break
        else:
            log.info("Failed to Find the valid context")
    context_dict = debugger.context.to_dict()
    context_string = context_dict["raw"]
    if src_name and line_number:
        context_string = "Result for line: {} in src: {}\n\n".format(line_number, src_name) + "\n\n" + context_string
    elif function_name:
        context_string = "Result for function: {}\n\n".format(function_name) + "\n\n" + context_string
    else:
        context_string = "Result for crash\n\n" + "\n\n" + context_string
    log.info("Got the context and registers")
    log.info("context_dict: %s", context_dict)
    return context_dict, context_string