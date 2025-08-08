import json
import os
import subprocess
import random
import string
import time
import logging

from pathlib import Path
from typing import Any, Dict, Tuple, Optional, Union, Generator
from functools import lru_cache
from contextlib import contextmanager


from difflib import SequenceMatcher
from shellphish_crs_utils.models import (
    POIReport,
    FunctionIndex,
    SourceLocation,
    BacktraceType,
)
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.instrumentation.dyva import DyvaInstrumentation
from shellphish_crs_utils.oss_fuzz.project import RunImageInBackgroundResult, InstrumentedOssFuzzProject, OSSFuzzProject

from debug_lib.agent.engine import debug_helper
from debug_lib.debuggers import GDBDebugger

log = logging.getLogger("dyva-utils")

def random_string(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def run_command(cmd, timeout=None, on_raise=None):
    try:
        # randomize stdout and stderr filenames because this is run in parallel
        suffix = random_string(length=10)
        stdout_filename = f"/tmp/cmd_stdout_{suffix}"
        stderr_filename = f"/tmp/cmd_stderr_{suffix}"

        with open(stdout_filename, "wb") as cmd_stdout, open(stderr_filename, "wb") as cmd_stderr:
            # .debug(f"Running command: {cmd}")
            pid = subprocess.Popen(cmd, shell=True, text=False, stdout=cmd_stdout, stderr=cmd_stderr)
            pid.communicate(timeout=timeout)
            exit_code = pid.returncode

    except subprocess.TimeoutExpired:
        log.error(" >>> ⏰ Timeout expired for command %s <<<", cmd, exc_info=True)
        pid.kill()
        exit_code = -1

    except subprocess.CalledProcessError:
        log.exception("Failed to run command %s", cmd, exc_info=True)
        exit_code = -1

    finally:
        with (
            open(stdout_filename, "r", encoding="utf-8", errors="replace") as cmd_stdout,
            open(stderr_filename, "r", encoding="utf-8", errors="replace") as cmd_stderr,
        ):
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()

        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)

        if exit_code == -1:
            log.error(" 🤡 Fatal error during %s\n%s\n%s\n%s", cmd, exit_code, cmd_stdout_text, cmd_stderr_text)
        elif exit_code != 0:
            log.error(" 🤡 Non-Fatal error during %s\n%s\n%s\n%s", cmd, exit_code, cmd_stdout_text, cmd_stderr_text)

        if on_raise and exit_code == -1:
            raise on_raise

        return exit_code, cmd_stdout_text, cmd_stderr_text

def extract_harness_class_name_from_poi(poi_report: POIReport) -> str:
    # Extract the stack trace

    class_name = None
    for trace in poi_report.stack_traces["main"].call_locations[::-1]:
        if (
            trace.type == BacktraceType.source
            and trace.source_location is not None
            and trace.source_location.java_info
            and trace.source_location.java_info.method_name
            and "fuzzerTestOneInput" in trace.source_location.java_info.method_name
        ):
            class_name = trace.source_location.java_info.class_path
            break

    return class_name


def extract_stack_trace_from_poi(poi_report: POIReport) -> Tuple[SourceLocation, str]:
    # Extract the stack trace

    for trace in poi_report.stack_traces["main"].call_locations:
        if (
            trace.type == BacktraceType.source
            and trace.source_location is not None
            and trace.source_location.full_file_path is not None
            and trace.source_location.function_index_signature
        ):
            break
    else:
        assert False, "No source trace found in the stack trace"

    crash_reason = poi_report.crash_reason

    if crash_reason:
        crash_reason += "  (May or may not be the actual reason)"
    log.info("trace.source_location: %s", trace.source_location)
    return trace.source_location, crash_reason


def get_file_contents_from_path(file_path: Path, function_indices: Path) -> set[str]:
    function_indices: Dict[str, str] = json.loads(function_indices.read_text())
    valid_files = set()
    for idx in range(len(file_path.parts)):
        path = Path(*file_path.parts[idx:])
        valid_files = {k.split(":")[1] for k in function_indices.keys() if str(path) in k}
        if valid_files:
            break

    return valid_files


def get_function_source(
    function_signature: str,
    file_path: Path,
    line_number: int,
) -> Union[FunctionIndex, Dict[str, Any]]:
    """
    This function is used to fetch the function source code using the function signature
    :param function_signature: The function signature to fetch the source code for
    :param file_path: The file path to fetch the source code for
    :param line_number: The line number to fetch the source code for

    :return: The function source code
    """

    try:
        function_info = debug_helper.FUNCTION_RESOLVER.get(function_signature)
    except KeyError:
        try:
            keys = list(debug_helper.FUNCTION_RESOLVER.resolve_with_leniency(function_signature))
            if not keys:
                keys = list(debug_helper.FUNCTION_RESOLVER.find_by_filename(str(file_path)))
            if keys and line_number:
                for key in keys:
                    new_info = debug_helper.FUNCTION_RESOLVER.get(key)
                    if new_info.start_line <= line_number <= new_info.end_line:
                        function_info = new_info
                        break
        except KeyError:
            function_info = None

    if not function_info:
        log.error("Function signature not found in the FUNCTIONS global variable ❌: %s", function_signature)
        return {"error": "Function signature not found in the FUNCTIONS global variable ❌"}

    return function_info


def format_function_index(function_info: FunctionIndex) -> str:
    """
    This function is used to convert the dictionary to source code
    """
    src_code = add_line_numbers_to_code(function_info.code, function_info.start_line, function_info.end_line)

    return_string = f"""
##FILE_PATH: {function_info.target_container_path}
##FUNCTION_NAME: {function_info.funcname}
##FUNCTION SIGNATURE: {function_info.signature}
##START_LINE: {function_info.start_line}
##ENDLINE: {function_info.end_line}
##CODE:
{src_code}
"""

    return return_string


def get_crash_context(
    function_info: FunctionIndex,
    crashing_line: int,
    input_data: Path,
    binary_path: Path,
    remote: str,
    crash: bool = False,
    use_jdb: bool = False,
) -> Dict[str, Any]:
    """
    :param crashing_function_src_dict: The code and metadata of the crashing function.
    :param crashing_line: The line number of the crashing function.
    :param input_data: The input data that caused the crash.
    :param binary_path: The path to the binary file.
    :param remote: The remote address.
    :param target_dir: The target directory.
    :return: A dictionary containing information about the crash context.
    """
    if function_info:
        if not function_info.code:
            log.error("Crashing function source code is empty: %s", function_info.target_container_path)
            return {"error": f"Crashing function source code is empty: {function_info.target_container_path}"}

        log.info("Getting crash context for %s:%d", function_info.target_container_path, crashing_line or -1)

    try:
        class_name = debug_helper.DYVA_STATE.class_name or function_info.class_name
        with debug_helper.get_new_debugger(binary_path=binary_path, input_data=input_data, class_name=class_name, remote=remote, debugger_type='jdb' if use_jdb else 'gdb') as debugger:
            if isinstance(debugger, GDBDebugger):
                source_file = function_info.target_container_path if function_info else None
            else:
                source_file = function_info.class_name if function_info else None

            trace_dict, _ = debug_helper.get_info_at_location(
                debugger=debugger,
                src_name=source_file,
                line_number=crashing_line,
                crash=crash,
            )
    except Exception as e:
        log.exception("Error getting crash context: %s", e, exc_info=True)
        log.info("Trying to get crash context without class name")
        debug_helper.DYVA_STATE.class_name = None
        with debug_helper.get_new_debugger(binary_path=binary_path, input_data=input_data, remote=remote, debugger_type='jdb' if use_jdb else 'gdb') as debugger:
            if isinstance(debugger, GDBDebugger):
                source_file = function_info.target_container_path if function_info else None
            else:
                source_file = function_info.class_name if function_info else None

            trace_dict, _ = debug_helper.get_info_at_location(
                debugger=debugger,
                src_name=source_file,
                line_number=crashing_line,
                crash=crash,
            )
    return trace_dict


def add_line_numbers_to_code(code: str, start_line: int, end_line: int, seek=False) -> str:
    """
    This function is used to add line numbers to the code
    :param code: The code to be formatted.
    :param start_line: The starting line number.
    :param end_line: The ending line number.
    :param seek: If True, the code will be sliced between start_line and end_line.
    """
    all_lines = code.strip().split("\n")
    if seek:
        formatted_lines = [f"{start_line + idx}: {line}" for idx, line in enumerate(all_lines[start_line:end_line])]
    else:
        formatted_lines = [f"{start_line + idx}: {line}" for idx, line in enumerate(all_lines)]
    return "\n".join(formatted_lines)


def split_function(name):
    "split the function name by `.` and `:`"
    name, sig = name.split(":") if ":" in name else (name, "")
    name_segs = name.split(".")
    return list(name_segs) + [sig] if sig else name_segs


def similarity(func_a: str, func_b: str) -> float:
    """
    Calculate the similarity between two function signatures.
    """
    return SequenceMatcher(None, split_function(func_a), split_function(func_b)).ratio()


def obtain_directory_structure_as_str(dir_path):
    """
    This function returns the directory structure as a string
    something like:
        dir_path
        ├── file1
        ├── file2
        └── subdir1/
    """
    directory_structure = ""
    all_files = os.listdir(dir_path)
    for file in all_files:
        directory_structure += f"├── {file}\n"
    return directory_structure


@contextmanager
def build_debug_and_run_image(port_dir: Path) -> Generator[Tuple[RunImageInBackgroundResult, int], None, None]:
    """
    Build a debug image for the target directory.
    :param oss_fuzz_project: The path to the oss-fuzz project.
    :param project_name: The name of the project.
    :param port_dir: The directory to store the port file.
    :return: The name of the debug image.
    """
    oss_fuzz_project = debug_helper.DYVA_STATE.oss_fuzz_project
    harness_location = debug_helper.DYVA_STATE.binary_path

    instrumented_project = InstrumentedOssFuzzProject(DyvaInstrumentation(), oss_fuzz_project.project_path)

    if oss_fuzz_project.project_language == LanguageEnum.jvm:
        # Create a jdbserver script that will be used to run the jdbserver.
        script_content, port = create_jdbserver_script(harness_location, port_dir)
        env = {}
    elif oss_fuzz_project.project_language in [LanguageEnum.c, LanguageEnum.cpp]:
        # Create a gdbserver script that will be used to run the gdbserver.
        script_content, port = create_gdbserver_script(harness_location, port_dir)
        env = {
            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "UBSAN_OPTIONS": "halt_on_error=1",
            "FUZZING_ENGINE": "libfuzzer",
            "SANITIZER": "address",
        }
        os.environ.update(env)
    else:
        raise ValueError(f"Unsupported language: {oss_fuzz_project.project_language}")

    script_path = oss_fuzz_project.artifacts_dir / "out" / "run_debug_server.sh"
    script_path.write_text(script_content)
    script_path.chmod(0o777)

    debug_image_name = instrumented_project.get_runner_image_name()

    env.update(
        {
            "RUN_FUZZER_MODE": "interactive",
            "TESTCASE": "/work/pov_input",
            "ARTIPHISHELL_FUZZER_INSTANCE_NAME": "run_pov",
            "ARTIPHISHELL_PROJECT_NAME": oss_fuzz_project.project_name,
            "ARTIPHISHELL_HARNESS_NAME": harness_location.name,
        }
    )
    background_runner = instrumented_project.image_run_background__local(
        debug_image_name,
        "bash",
        "/out/run_debug_server.sh",
        volumes={oss_fuzz_project.artifacts_dir / "built_src": "/src", 
                 oss_fuzz_project.artifacts_dir / "out": "/out", 
                 port_dir: str(port_dir)},
        extra_env=env,
        extra_docker_args=["--network", "host", "-w", "/out"],
    )

    port_file = port_dir.joinpath(str(port))
    ip_address = get_container_ip_address(port_file)
    log.info("IP Address: %s:%s", ip_address, port)
    debug_helper.DYVA_STATE.debug_remote = f"{ip_address}:{port}"

    try:
        yield background_runner
    finally:
        cleanup_container(background_runner.container_name, port_dir.joinpath(str(port)))


def create_gdbserver_script(harness_location: Path, port_dir: Path) -> Tuple[str, int]:
    """
    Create a gdbserver script that will be used to run the gdbserver.
    """
    while port := random.randint(10000, 65535):
        if not port_dir.joinpath(str(port)).exists():
            break

    port_file = port_dir.joinpath(str(port))
    script = f"""
#!/usr/bin/env bash
set -x
export DEFAULT_INTERFACE=$(route  | grep default | awk '{{print $8}}')
echo $(ifconfig $DEFAULT_INTERFACE | grep 'inet ' | awk '{{print $2}}') > {port_file}

if [ ! -f "/out/{harness_location.name}" ]; then
    echo "Error: Harness file /out/{harness_location.name} does not exist" >&2
    exit 1
fi
env
while true; do
    gdbserver :{port} /out/{harness_location.name} $@
    GDB_PID=$!
    kill -9 $GDB_PID
done
"""
    return script, port


def create_jdbserver_script(harness_location: Path, port_dir: Path) -> Tuple[str, int]:
    """
    Create a jdbserver script that will be used to run the gdbserver.
    """
    while port := random.randint(10000, 65535):
        if not port_dir.joinpath(str(port)).exists():
            break

    port_file = port_dir.joinpath(str(port))
    harness_name = harness_location.name
    script = f"""
#!/usr/bin/env bash
set -x
export DEFAULT_INTERFACE=$(route  | grep default | awk '{{print $8}}')
echo $(ifconfig $DEFAULT_INTERFACE | grep 'inet ' | awk '{{print $2}}') > {port_file}

if [ ! -f "/out/{harness_name}" ]; then
    echo "Error: Harness file /out/{harness_name} does not exist" >&2
    exit 1
fi

export PYTHONUNBUFFERED=1
while true; do
    python /pyjdb/start_jdb_server.py {port}
    JDB_PID=$!
    kill -9 $JDB_PID
done
"""
    return script, port


def get_container_ip_address(target_file: Path) -> str:
    while not target_file.exists():
        time.sleep(1)

    return target_file.read_text().strip()


def cleanup_container(container_name: str, port_file: Path):
    if port_file.exists():
        port_file.unlink()

    if container_name:
        subprocess.run(["docker", "kill", container_name])
        subprocess.run(["docker", "rm", container_name])

def crash_report_from_dyva_state() -> Dict[str, Any]:
    """
    This function is used to get the crash report from the dyva state
    """
    debug_helper.DYVA_STATE.crash_report = crash_report(
        poi_report=debug_helper.DYVA_STATE.poi_report,
        binary_path=debug_helper.DYVA_STATE.binary_path,
        input_data=debug_helper.DYVA_STATE.input_data,
        debug_remote=debug_helper.DYVA_STATE.debug_remote,
        oss_fuzz_project=debug_helper.DYVA_STATE.oss_fuzz_project,
        arbitrary_crash=debug_helper.DYVA_STATE.arbitrary_crash,
    )
    return debug_helper.DYVA_STATE.crash_report


def crash_report(
    poi_report: POIReport,
    binary_path: Path,
    input_data: Path,
    debug_remote: str,
    oss_fuzz_project: OSSFuzzProject,
    arbitrary_crash: bool,
) -> Dict[str, Any]:
    """Get the crash report, generating it if necessary"""

    log.info("Harness path: %s exists: %s", binary_path, binary_path.exists())

    if not arbitrary_crash:
        trace, crash_reason = extract_stack_trace_from_poi(poi_report)

        function_info = get_function_source(
            trace.function_index_signature,
            trace.full_file_path,
            trace.line_number,
        )

        crashing_context = None

        if oss_fuzz_project.project_language != LanguageEnum.jvm:
            message = None
            with debug_helper.get_new_debugger_from_dyva() as debugger:
                # debugger.raw("set follow-fork-mode child true")
                debugger.run()
                if debugger.context.frame.addr is not None:
                    message = debugger.raw("bt full")

            if message is None:
                with debug_helper.get_new_debugger_from_dyva() as debugger:
                    debugger.raw("set follow-fork-mode child")
                    debugger.run()
                    if debugger.context.frame.addr is not None:
                        message = debugger.raw("bt full")
                        debug_helper.DYVA_STATE.should_follow_child = True


            if message is None:
                with debug_helper.get_new_debugger_from_dyva() as debugger:
                    debugger.raw("set follow-exec-mode same")
                    debugger.raw("catch syscall exit_group")
                    debugger.run()
                    if debugger.context.frame.addr is not None:
                        message = debugger.raw("bt full")
                        debug_helper.DYVA_STATE.should_catch_exit = True

            if message is not None:
                full_bt = '\n'.join(x['payload'] for x in message if x.get("payload") is not None)
                crashing_context = {"backtrace": full_bt, "frame": {"function": trace.function_name, "line_no": trace.line_number, "file": trace.full_file_path, "src_line": trace.line_text}}
            else:
                crashing_context = {"backtrace": str(poi_report.stack_traces["main"]), "frame": {"function": trace.function_name, "line_no": trace.line_number, "file": trace.full_file_path, "src_line": trace.line_text}}

        else:
            class_name = extract_harness_class_name_from_poi(poi_report)
            debug_helper.DYVA_STATE.class_name = class_name
            crashing_context = get_crash_context(
                function_info,
                trace.line_number,
                Path("/work/pov_input"),
                binary_path,
                debug_remote,
                crash=True,
                use_jdb=True,
            )

        relevant_trace = {
            "function_name": trace.function_name,
            "function_signature": trace.function_index_signature,
            "line_number": trace.line_number,
            "line_text": trace.line_text,
        }

    else:
        crashing_context = get_crash_context(
            None,
            None,
            Path("/work/pov_input"),
            binary_path,
            debug_remote,
            crash=True,
            use_jdb=oss_fuzz_project.project_language == LanguageEnum.jvm,
        )
        crash_reason = "Unknown"

        function_info = get_function_source(
            crashing_context["frame"]["function"],
            Path(crashing_context["frame"]["file"]),
            int(crashing_context["frame"]["line_no"]),
        )

        relevant_trace = {
            "function_name": crashing_context["frame"]["function"],
            "function_signature": crashing_context["frame"]["function"],
            "line_number": crashing_context["frame"]["line_no"],
            "line_text": crashing_context["frame"]["src_line"],
        }

    crashing_function_src = format_function_index(function_info)

    crashing_input = input_data.read_bytes()
    crashing_input_size = len(crashing_input)
    if crashing_input_size > 1024:
        crashing_input = crashing_input[:1024]
        crashing_input += b"\n\n[truncated]"

    crash_report = {
        "root_dir": oss_fuzz_project.artifacts_dir,
        "crash_reason": crash_reason,
        "crash_file": crashing_context["frame"]["file"],
        "crash_line_number": crashing_context["frame"]["line_no"],
        "crashing_function_src": crashing_function_src,
        "crashing_context": crashing_context,
        "stack_trace": relevant_trace,
        "crashing_input": crashing_input,
        "crashing_input_size": crashing_input_size,
    }

    log.info("Crashing Location: %s", relevant_trace)
    return crash_report
