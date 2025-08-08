import argparse
import pathlib
import tempfile
import shutil
import re
import random
from collections import defaultdict

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject, InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation import griller_flag

from agentlib import Agent, AgentWithHistory, LLMFunction, tools 
from agentlib.lib.common.parsers import BaseParser

CP : OSSFuzzProject = None
BITCODE : pathlib.Path = None
OUTPUT_FILE : pathlib.Path = None

def parse_undefined_references(log_text):
    # Regex to match: /path/to/file:line: undefined reference to `function'
    pattern = re.compile(r'(?P<file>[^:]+):(?P<line>\d+): undefined reference to [`\'](?P<func>[^\'`]+)[`\'"]')
    grouped_by_file = defaultdict(set)
    grouped_by_prefix = defaultdict(set)

    for match in pattern.finditer(log_text):
        file = match.group('file')
        func = match.group('func')
        grouped_by_file[file].add(func)
        prefix = func.split('_', 1)[0] if '_' in func else func
        grouped_by_prefix[prefix].add(func)

    unique_picks = set()

    # Pick one at random from each file group
    for file, funcs in grouped_by_file.items():
        if funcs:
            # sort the functions in the group in ascending order
            sorted_funcs = sorted(funcs)
            # pick the first one
            func = sorted_funcs[0]
            unique_picks.add(func)

    # Pick one at random from each prefix group
    for prefix, funcs in grouped_by_prefix.items():
        if funcs:
            # sort the functions in the group in ascending order
            sorted_funcs = sorted(funcs)
            # pick the first one
            func = sorted_funcs[0]
            unique_picks.add(func)

    # Print unique set
    print("Unique set of functions:")
    for func in unique_picks:
        print(func)
    print("======================")

    return unique_picks

def _build_target(bitcode, flags):
    """
    Build the target with the given bitcode and flags.
    """
    with tempfile.TemporaryDirectory(prefix="/shared/griller-tmp-") as tmp_dir:
        shutil.copy(bitcode, f"{tmp_dir}/griller_prog.bc")
        with open(f"{tmp_dir}/griller_flags.txt", "w") as f:
            f.write(flags)

        build_result = CP.build_target(
            sanitizer="address", 
            extra_files={
                f"{tmp_dir}/griller_prog.bc" : "/grill/griller_prog.bc",
                f"{tmp_dir}/griller_flags.txt" : "/grill/griller_flags.txt"
            }, 
        )
    return build_result

@tools.tool
def try_building_project(linker_flags: str) -> str:
    """
    Try to build the project with the given linker flags (that you provide).
    You can provide multiple linker flags (for example: -lfoo -lbar).
    If the build fails, return either the undefined function or the error message of the build.
    """
    build_result = _build_target(BITCODE, linker_flags)

    undef = parse_undefined_references(build_result.stderr.decode("latin-1"))
    response = "Tried Building with linker flags: " + linker_flags + "\n"
    if len(undef) > 0:
        response += "There were still Undefined references: " + ", ".join(list(undef)[0:100]) + "\n"
    else:
        response += "Here's the build result: " + trim(build_result.stderr.decode("latin-1")) + "\n"        
    return response

@tools.tool
def game_over(final_linker_flags : str) -> str:
    """
    This tool is used to indicate that the game is over.
    It is used to stop the agent from trying to build the project.

    The agent should runeach round to see if you can find the missing linker flags this tool with the final set of linker flags, which is sure to build the project.
    """
    with open(OUTPUT_FILE, "w") as f:
        f.write(final_linker_flags)
    
    # compile with the final linker flags and output the result to the output file
    

class Bengali(Agent[str, str]):
    prompts_dir = pathlib.Path(__file__).parent / "prompts"
    __SYSTEM_PROMPT_TEMPLATE__ = str(prompts_dir / "bengali.system.j2")
    __LLM_MODEL__ = "claude-3.7-sonnet"
    __USER_PROMPT_TEMPLATE__ = str(prompts_dir / "bengali.user.j2")

    # In agentlib and langchain, all agents are serializable objects
    #   using pydantic you define your instance member variables like this
    #   instead of using __init__ and setting on self
    # See https://docs.pydantic.dev/latest/concepts/models/

    def get_available_tools(self):
        return [
            # Import some predefined tools
            tools.give_up_on_task,
            # Here is our own tool
            try_building_project,
            game_over,
        ]
                            
def setup_project(args):
    global CP, BITCODE, OUTPUT_FILE
    CP = InstrumentedOssFuzzProject(
        project_id = args.project_id,
        oss_fuzz_project_path = args.oss_fuzz_project_path,
        use_task_service = False, # always spwan a new container on the same host
        instrumentation = griller_flag.GrillerFlagInstrumentation()
    )
    
    if args.local_run:
        print("[LOCAL_RUN] Building the builder and runner images...\n")
        CP.build_builder_image()
        CP.build_runner_image()
        

    # find first .bc file in the artifacts directory, non-recursive
    assert args.bitcode.is_file(), f"Bitcode file {args.bitcode} does not exist"
    BITCODE = args.bitcode
    OUTPUT_FILE = args.output_file

def main():
    # Load OSSFuzz project    
    setup_project(args())
    build_result = _build_target(BITCODE, "\n")
    print("[BUILD_RESULT] ", build_result.stderr)
    # undef = parse_undefined_references(build_result.stderr.decode("latin-1"))
    # import IPython; IPython.embed()
    
    a = Bengali()
    res = a.invoke(dict(
        error_message = trim(str(build_result.stderr)) # Provide template variables this way
    ))
    
    
    
def trim(text):
    if len(text) > 500:
        return text[:500]
    else:
        return text


def args():
    parser = argparse.ArgumentParser(description="Get Compiler Flags")
    parser.add_argument('--project_id', required=True, type=pathlib.Path)
    parser.add_argument('--oss_fuzz_project_path', required=True, type=pathlib.Path)
    parser.add_argument("--local_run", action="store_true", help="Run locally", default=False)
    parser.add_argument("--bitcode", required=True, type=pathlib.Path)
    parser.add_argument("--output_file", required=True, type=pathlib.Path)

    return parser.parse_args()

if __name__ == "__main__":
    main()