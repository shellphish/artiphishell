import argparse
import yaml
import time
import os
import logging
import json
import re

from typing import List
from pathlib import Path
from universal_dbg.debuggers import Debugger, GDBDebugger
from universal_dbg.debuggers.context import DebugContext
from rich.logging import RichHandler
from rich.console import Console
from pprint import pformat

import dyva_build

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)]
)
logger = logging.getLogger("dyva")
logger.setLevel(logging.DEBUG)

def get_args():
    argparser = argparse.ArgumentParser(description='invguy-build')

    argparser.add_argument('--target-metadata', type=Path, help='Target metadata', required=True)
    argparser.add_argument('--target-dir', type=Path, help='Target program source code', required=True)
    argparser.add_argument('--harness-info', type=Path, help='Target harness info', required=True)
    argparser.add_argument("--poi-report", type=Path, default="poi_report", help="Path to poi_report", required=True)
    argparser.add_argument("--crashing-input", type=Path, help="Path to crashing input", required=True)
    argparser.add_argument("--function-indices", type=Path, help="Path to function indices folder", required=True)
    argparser.add_argument("--function-json", type=Path, help="Path to function json file", required=True)
    argparser.add_argument("--output-path", type=Path, help="Path to output_path", required=True)

    args = argparser.parse_args()
    return args

def find_binary_and_breakpoint_locations(metadata: dict, poi_report: Path, target_dir: Path, function_json: Path, function_indices: Path):
    with poi_report.open("r") as f:
        data = yaml.safe_load(f)
    stack_traces = data["stack_traces"]
    
    full_json = json.loads(function_indices.read_bytes())

    break_locs = []
    sources = sorted(metadata["cp_sources"].keys(), key=lambda x: len(x), reverse=True)
    for frames in stack_traces:
        for frame in frames["call_locations"]:
            fp = frame["relative_file_path"]
            logger.info("Looking for breakpoint in %s", frame)
            for source in sources:
                logger.debug("Looking for source %s in %s", source, fp)
                if fp.find(source) > 0:
                    file = target_dir / "src" / fp[fp.find(source):]
                    break
            else:
                continue
            line_no = frame["line_number"]
            func_idx = full_json.get(frame["key_index"])
            global_vars = []
            if func_idx is not None:
                global_vars = json.loads((function_json / func_idx).read_bytes()).get("global_variables", [])
            break_locs.append((str(file), str(line_no), [x["name"] for x in global_vars if "name" in x]))
            logger.debug("Added breakpoint: %s", break_locs)

    return break_locs

def translate_context_to_dict(context: DebugContext, target_dir: Path):
    out_context = {"frame": {
                                "args": [{"type": l.type, "name": l.name, "value": l.value} for l in (context.frame.args or [])],
                                "file": str(context.frame.file),
                                "line_no": context.frame.line,
                                "src_line": context.frame.text,
                                "function": context.frame.function
                    },
                   "backtrace": [str(b) for b in context.backtrace.bt],
                   "locals": [{"type": l.type, "name": l.name, "value": l.value} for l in context.locals],
                   "globals": [{"type": l.type, "name": l.name, "value": l.value} for l in context.globals],
                   "raw": str(context)
                   }
    return out_context
def run_debugging_steps(debugger: Debugger, break_locs: List[str], target_dir: str) -> List[DebugContext]:
    valid_locations = set()
    debugger.raw("set follow-fork-mode child true")
    debugger.raw("set breakpoint pending on")
    for file, line_no, global_vars in break_locs:
        file = Path(file).name
        logger.info("Setting breakpoint at %s:%s", file, line_no)
        break_loc = f"{file}:{line_no}"
        if break_loc not in valid_locations:
            logger.debug(debugger.set_breakpoint(break_loc))
        valid_locations.add(break_loc)
        for g in global_vars:
            debugger.track_global(g)
    

    logger.info("BREAKPOINTS: %s", break_locs)
    contexts = {}
    idx = 0
    while not debugger.exited:
        debugger.continue_execution()
        logger.info(str(debugger.context))
        if debugger.context.frame.file is None:
            logger.critical("HIT NO FILE")
            continue
        elif debugger.context.frame.file == ".": 
            logger.critical("HIT FILE IS .")
            continue
        elif debugger.context.frame.line < 0:
            logger.critical("HIT NO LINE")
            continue
        elif not debugger.context.backtrace.bt:
            logger.critical("HIT NO BT")
            continue
        elif debugger.context.backtrace.bt[0].file is None:
            logger.critical("DON'T CARE ABOUT THIS BT")
            continue
        elif any(x.endswith(f"{debugger.context.frame.file}:{debugger.context.frame.line}") for x in valid_locations):
            logger.critical("HIT NOT APPLICABLE FILE %s:%s", debugger.context.frame.file, debugger.context.frame.line)
            logger.critical(valid_locations)
            continue
        current_file = Path(debugger.context.frame.file)
        try:
            source_loc = current_file.parts.index("src")
            relative_path = '/'.join(current_file.parts[source_loc:])
            if (target_dir / relative_path).exists():
                debugger.context.frame.file = relative_path
                print("NEW_FILE", debugger.context.frame.file)
        except ValueError as e:
            print("ERROR: %s - %s", debugger.context.frame.file, e)
            pass
        out_context = translate_context_to_dict(debugger.context, target_dir)
        key = f"{debugger.context.frame.file}:{debugger.context.frame.line}"
        contexts[key] = {"context": out_context, "hit": idx}
        idx += 1
    return [x[1]["context"] for x in sorted(contexts.items(), key=lambda kv: kv[1]["hit"])]

def main():
    args = get_args()
    dyva_build.build_and_run(args.target_dir, args.target_metadata, args.harness_info, args.crashing_input)
    with args.target_metadata.open("r") as f:
        metadata = yaml.safe_load(f)
    break_locs = find_binary_and_breakpoint_locations(metadata, args.poi_report, args.target_dir, args.function_json, args.function_indices)
    

    socket_path = args.target_dir / "src" / "gdb.socket"
    while not socket_path.exists():
        logger.info(f"waiting for the socket at {socket_path=}")
        time.sleep(1)
    with args.harness_info.open("r") as f:
        harness_info = yaml.safe_load(f)
    binary_path = args.target_dir / harness_info["cp_harness_binary_path"] 
    os.chdir(args.target_dir / Path(harness_info["cp_harness_source_path"]).parent)

    debugger = None
    if metadata["language"] == "c":
        debugger = GDBDebugger(binary_path, argv=["/src/input"], remote=str(socket_path))
    
    if debugger is not None:
        output = run_debugging_steps(debugger, break_locs, args.target_dir)
        context_out = {"debug_trace": output}
        with args.output_path.open("w+") as f:
            yaml.safe_dump(context_out, f)

if __name__ == '__main__':
    main()