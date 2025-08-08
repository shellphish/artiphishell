import unittest
import sys
import os
from common import SimpleProgram
from kumushi.tracing.dumb_tracer import DumbCallTracer
from pathlib import Path
import re

TARGETS = Path(__file__).parent.absolute() / "targets"


class TestKumuShiCore(unittest.TestCase):
    """
    Test the core functionality of KumuShi
    """
    def test_trace_collection(self):
        # Setup tracer for use
        source_root = TARGETS / "hamlin/challenge/src"
        run_script = TARGETS / "hamlin/challenge/run.sh"
        crashing_input = TARGETS / "hamlin/alerting_inputs/crash_input"
        prog = SimpleProgram(run_script, source_root, crashing_input, None, None, "C++", parse_code=True)
        tracer = DumbCallTracer(prog)
        tracer.instrument_functions()

        # Test every function parsed hase a trace added
        for file_path, functions in tracer.sorted_functions.items():
            with open(file_path, 'r') as source_file:
                raw = source_file.read()
                regex = r"TRACE_HIT\|(.*)\|"
                matches = re.findall(regex, raw)
                assert len(matches) == len(functions)

        # Build program, and setup tracing environment trace the program
        prog.compile()
        env = os.environ.copy()
        env["CHESS"] = "1"
        call_trace = tracer.trace("hamlin.bin", env)

        # Remove junk on filesystem
        tracer.cleanup()


if __name__ == "__main__":
    unittest.main(argv=sys.argv, buffer=True)
