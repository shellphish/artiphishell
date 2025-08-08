

import os
import hashlib
from coveragelib import Tracer, Pintracer
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML


oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
         os.path.join(seeds, "merda2")
        ]

def test_covguy_not_aggregate_simple_parser():
    with Pintracer(oss_fuzz_repo, "pov_harness", debug_mode=True, aggregate=False) as tracer:
        res = tracer.trace(*seeds)
        the_res = res[0]
        the_res.sort()
        res_0 = str(the_res)
        md5_res_0 = hashlib.md5(res_0.encode()).hexdigest()

        if md5_res_0 != "4df93b4b56908503e256677dd79adf33":
            print(f"MD5 of result is {md5_res_0}, expected 4df93b4b56908503e256677dd79adf33")
            #print(f"Results from coverage: {res}")
            assert False

print("Test: test_covguy_pintracer_full")
test_covguy_not_aggregate_simple_parser()

print("*******All tests passed!*******")