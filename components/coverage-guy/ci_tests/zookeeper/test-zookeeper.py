
import os
import hashlib
# THese are needed for timeout tests
import concurrent.futures
import time

from coveragelib import Tracer
from coveragelib.parsers.line_coverage import Java_LineCoverageParser_Jacoco


oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds_dir = os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds_dir is not None)

seeds = [
            os.path.join(seeds_dir, "timeout-seed"),
            os.path.join(seeds_dir, "seed_0.bin"),
            os.path.join(seeds_dir, "seed_1.bin"),
        ]

# Lets write a seed that contains 'ARTIPHISHELL' inside it in the seeds dir
open(os.path.join(seeds_dir, "dummy-seed"), "wb").write(b"ARTIPHISHELL")

dummy_seed = [
    os.path.join(seeds_dir, "dummy-seed")
]

def calc_hash(res):
    # For every element in the list, compute the md5
    md5s = []
    for r in res:
        r = [ str(x) for x in list(r) ]
        r.sort()
        r_md5 = hashlib.md5(str(r).encode()).hexdigest()
        md5s.append(r_md5)

    # Sort md5s alphabetically
    md5s.sort()
    # Compute the md5 of the md5s
    md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
    return md5_res

def test_myroco_timeout_seed():
    testing_timeout = 10
    with Tracer(oss_fuzz_repo, "MessageTrackerPeekReceivedFuzzer", debug_mode=True, include_seeds_metadata=True, timeout_per_seed=testing_timeout) as tracer:
        # We need to get myroco up and running so lets use a dummy seed that doesn't cause timeout
        res, meta = tracer.trace(dummy_seed)
        print("[*] The meta is: ", meta)
        # Okay now myroco should be ready for timeout tests
        print("[*] Finished setting up myroco and tracer. Now testing timeout!")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(tracer.trace, *seeds)
            try:
                res, meta = future.result(timeout=60)
                for seed_meta in meta.keys():
                    if meta[seed_meta]['tracing_time'] > testing_timeout:
                        print(f"Seed {meta[seed_meta]['seed']} took {meta[seed_meta]['tracing_time']} seconds to trace, expected {testing_timeout} seconds")
                        assert False
            except concurrent.futures.TimeoutError:
                print("We shouldn't reach here, the test should timeout")
                executor.shutdown(wait=False, cancel_futures=True)
                assert False

        # 74e2066654e7fa3269e54d135fc80e53
        md5_res = calc_hash(res)
        if md5_res != "81dcefd7509fb9e1f3b65ff31ec9a3ae":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False

def test_covguy_not_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "MessageTrackerPeekReceivedFuzzer", debug_mode=True, include_seeds_metadata=True) as tracer:
        # This is for execution without myroco initialized       
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)

        if md5_res != "8b47845a4ed5a75f9ac7553e501a8c9d":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            # assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)

        # Calculate the md5 of the string 
        if md5_res != "81dcefd7509fb9e1f3b65ff31ec9a3ae":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_not_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "MessageTrackerPeekReceivedFuzzer", debug_mode=True, include_seeds_metadata=True, parser=Java_LineCoverageParser_Jacoco()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)

        if md5_res != "":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)
        
        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        
        if md5_res != "":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)

        if md5_res != "":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        md5_res = calc_hash(res)

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "":
            print(f"MD5 of result is {md5_res}, expected ")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True, parser=Java_LineCoverageParser_Jacoco()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        r = str(res)
        r_md5 = hashlib.md5(str(r).encode()).hexdigest()
        md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "e13fb7a06857c619a3f61fdd98e84901":
            print(f"MD5 of result is {md5_res}, expected e13fb7a06857c619a3f61fdd98e84901")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        r = str(res)
        r_md5 = hashlib.md5(str(r).encode()).hexdigest()
        md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "e13fb7a06857c619a3f61fdd98e84901":
            print(f"MD5 of result is {md5_res}, expected e13fb7a06857c619a3f61fdd98e84901")
            #print(f"Results from coverage: {res}")
            assert False


print("Test: test_myroco_timeout_seed")
test_myroco_timeout_seed()
test_covguy_not_aggregate_simple_parser()
print("*******All tests passed!*******")