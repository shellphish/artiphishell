

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
         os.path.join(seeds, "crash-assimp"),
        ]

def test_covguy_not_aggregate_simple_parser():
    with Pintracer(oss_fuzz_repo, "assimp_fuzzer", debug_mode=True, aggregate=False) as tracer:
        res = tracer.trace(*seeds)
        assert isinstance(res[0], list)  
        res_0 = res[0]
        res_0.sort()
        res_0_str = str(res)
        md5_res_0 = hashlib.md5(res_0_str.encode()).hexdigest()

        if md5_res_0 != "7cabf3574002f6ea70c30672ec74b13f":
            print(f"MD5 of result is {md5_res_0}, expected 7cabf3574002f6ea70c30672ec74b13f")

            assert False

print("Test: test_covguy_pintracer_full")
test_covguy_not_aggregate_simple_parser()

# TODO: implement test for indirect branch tracking

print("*******All tests passed!*******")