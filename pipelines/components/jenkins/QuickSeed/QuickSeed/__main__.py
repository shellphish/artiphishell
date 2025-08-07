import argparse
import logging
import queue
from pathlib import Path
import os
import sys
import tempfile
import yaml
from typing import List
import time
import QuickSeed
from subprocess import run
from .manager import (
    Producer,
    HarnessConsumer,
    FuzzerBlockerProducer,
    FuzzerBlockerConsumer,
    ConsumerProxy,
    FilterPoisConsumer,
)
from .utils import setup_aicc_target, WorkDirContext

_l = logging.getLogger("QuickSeed")
_l.setLevel(logging.DEBUG)

from QuickSeed.data import Program
from QuickSeed.parser import TaintParser

TESTDIR = Path(os.path.dirname(os.path.dirname(__file__))) / "tests"

# REPORT = TESTDIR / "resource/command_injection_call_graph.json"
# JAZZER_SANITIZER = TESTDIR / "resource/jazzer_sanitizer.json"
JAZZER_SANITIZER = Path(os.path.dirname(__file__)) / "jazzer_sanitizer.json"


def work(
    target_dir, func_index_path, source_func_dir, benign_dir, crash_dir, coverage_dir, report
):
    """
    Set up the queueing system for us to send harness request to LLM
    """

    q = queue.Queue()
    model = "gpt-4o"

    dict = {"src_root": target_dir, "report": report}
    program = Program(**dict)
    taint_parser = TaintParser(program, source_func_dir, func_index_path)

    if not coverage_dir:
        
        producer_codeql = Producer(
            taint_parser,
            JAZZER_SANITIZER,
            q,
            name="CODEQL Parser",
        )
        producer_codeql.start()
        producer_codeql.wait_finish()
        consumer_llm = HarnessConsumer(model, q, benign_dir, crash_dir, target_dir, name="LLM")
        consumer_proxy = ConsumerProxy(q)
        consumer_proxy.add_worker(consumer_llm)
    else:
        # Producer start
        producer_fuzzer_blocker = FuzzerBlockerProducer(
            q,
            taint_parser,
            coverage_dir,
            name="fuzzer_blocker",
        )
        producer_fuzzer_blocker.start()
        producer_fuzzer_blocker.wait_finish()
        consumer_fuzz_blocker = FuzzerBlockerConsumer(
            q, model, name="Fuzzer Blocker Detection"
        )
        consumer_filter_pois = FilterPoisConsumer(
            q,
            model,
            JAZZER_SANITIZER,
            taint_parser,
            benign_dir=benign_dir,
            crash_dir=crash_dir,
            name="filter interesting pois and generate seeds",
        )
        consumer_proxy = ConsumerProxy(q)
        
        consumer_proxy.add_worker(consumer_fuzz_blocker)
        consumer_proxy.add_worker(consumer_filter_pois)


    consumer_proxy.start()
    consumer_proxy.wait_finish()




def extract_source_func_dir(func_dir, target_path) -> List[Path]:
    _l.debug(f"{target_path} is path")
    with open(Path(target_path) / "project.yaml", "r") as f:
        description = yaml.safe_load(f)
    return list(map(lambda x: Path(func_dir) / x, description["cp_sources"].keys()))

def check_yaml(file_path: Path):
    # Check if file exists
    if not file_path.exists():
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    # Check if file is empty
    if file_path.stat().st_size == 0:
        raise ValueError(f"The file {file_path} is empty.")



def main():
    _l.debug("start the cli")
    parser = argparse.ArgumentParser(
        description="""
        The QuickSeed CLI
        """,
        epilog="""
        Examples:
        QuickSeed --version
        """,
    )
    parser.add_argument(
        "--version", "-v", action="version", version=QuickSeed.__version__
    )
    parser.add_argument("-t", "--target", type=Path)#default=DEFAULT_TARGET)
    parser.add_argument("--func-dir", type=Path)
    parser.add_argument("--func-index", type=Path)
    parser.add_argument("--coverage-dir", type=Path)
    parser.add_argument("--report", type=Path)

    parser.add_argument(
        "--benign-dir",
        type=Path,
        help="Output Directory for benign seeds",
    )

    parser.add_argument(
        "--crash-dir",
        help="Ouput Directory for crash seeds"
    )
    parser.add_argument(
        "--target-root",
        help="AIXCC target root"
    )
    args = parser.parse_args()
    target_root = args.target_root
    target_dir = args.target
    func_dir = args.func_dir
    yaml_report = args.report
    func_index_path = args.func_index
    coverage_dir = args.coverage_dir
    crash_dir = args.crash_dir
    benign_dir = args.benign_dir

    check_yaml(yaml_report)
    _l.debug(f"benign dir is {benign_dir}")
    _l.debug(f"crash_dir is {crash_dir}")
    with WorkDirContext(Path(target_root)):
        _l.debug(f"check dir exist {Path(target_root).exists()}")
        p = run(
                ["./run.sh", "build"],
            capture_output=True,
            text=True,
            #errors="ignore",
            )
        cmd = " ".join([str(Path(target_root) / "run.sh"), "build"])
        _l.debug(f"cmd is {cmd}")
        _l.debug(f"building, error is {p.stderr}, \n stdout is {p.stdout}")
        work(
            Path(target_root),
            func_index_path,
            func_dir,
            benign_dir,
            crash_dir,
            coverage_dir,
            yaml_report,
        )

    exit(0)


if __name__ == "__main__":
    main()
