
import os
import hashlib

from coveragelib import Yajta

oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
        os.path.join(seeds, "empty"),
        os.path.join(seeds, "050764bb7d2fe57ea75ff1a2f09e8a62")
       ]


def test_covguy_yajta_trace():
    with Yajta(oss_fuzz_repo, "Zip4jFuzzer", debug_mode=True) as tracer:
        print(" - Run 1")
        res = tracer.trace(*seeds)
        res_0 = str(res[0])
        res_1 = str(res[1])
        md5_res_0 = hashlib.md5(res_0.encode()).hexdigest() 
        md5_res_1 = hashlib.md5(res_1.encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")
        if md5_res_0 != "7e3becff9c6f006e0c84d7f656060662":
            print(f"MD5 of result is {md5_res_0}, expected 7e3becff9c6f006e0c84d7f656060662")
            print(f"Results from coverage: {res}")
            assert False
        if md5_res_1 != "eecf3591a60a49354f03bbcd7571f4a6":
            print(f"MD5 of result is {md5_res_1}, expected eecf3591a60a49354f03bbcd7571f4a6")
            print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res = tracer.trace(*seeds)
        res_0 = str(res[0])
        res_1 = str(res[1])
        md5_res_0 = hashlib.md5(res_0.encode()).hexdigest() 
        md5_res_1 = hashlib.md5(res_1.encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")
        if md5_res_0 != "7e3becff9c6f006e0c84d7f656060662":
            print(f"MD5 of result is {md5_res_0}, expected 7e3becff9c6f006e0c84d7f656060662")
            print(f"Results from coverage: {res}")
            assert False
        if md5_res_1 != "eecf3591a60a49354f03bbcd7571f4a6":
            print(f"MD5 of result is {md5_res_1}, expected eecf3591a60a49354f03bbcd7571f4a6")
            print(f"Results from coverage: {res}")
            assert False


print("Test: test_covguy_yajta_trace")
test_covguy_yajta_trace()

print("*******All tests passed!*******")
