
import os
import hashlib

from coveragelib import Tracer
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML


oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
         os.path.join(seeds, "empty"),
         os.path.join(seeds, "e5589ae7e6c75b33568a120c42b32f14"),
         os.path.join(seeds, "e5589ae7e6c75b33568a120c42b32f14"),
         os.path.join(seeds, "empty"),
         os.path.join(seeds, "merda2")
        ]


def test_covguy_not_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "fuzz_cups", debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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

        if md5_res != "16f70bc7dc6a43e90a991b0dd2b043d6":
            print(f"MD5 of result is {md5_res}, expected 16f70bc7dc6a43e90a991b0dd2b043d6")
            print(f"Results from coverage: {res}")
            assert False
        
        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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

        if md5_res != "16f70bc7dc6a43e90a991b0dd2b043d6":
            print(f"MD5 of result is {md5_res}, expected 16f70bc7dc6a43e90a991b0dd2b043d6")
            print(f"Results from coverage: {res}")
            assert False

def test_covguy_not_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "fuzz_cups", debug_mode=True, include_seeds_metadata=True, parser=C_LineCoverageParser_LLVMCovHTML()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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

        if md5_res != "e92c2b7adadeebff30c8f80103f37143":
            print(f"MD5 of result is {md5_res}, expected e92c2b7adadeebff30c8f80103f37143")
            print(f"Results from coverage: {res}")
            assert False
        
        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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

        if md5_res != "e92c2b7adadeebff30c8f80103f37143":
            print(f"MD5 of result is {md5_res}, expected e92c2b7adadeebff30c8f80103f37143")
            print(f"Results from coverage: {res}")
            assert False
        

def test_covguy_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "fuzz_cups", aggregate=True, debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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
        if md5_res != "323870c5c7d4abb5191db7b8355b8904":
            print(f"MD5 of result is {md5_res}, expected 323870c5c7d4abb5191db7b8355b8904")
            print(f"Results from coverage: {res}")
            assert False
        

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
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
        if md5_res != "323870c5c7d4abb5191db7b8355b8904":
            print(f"MD5 of result is {md5_res}, expected 323870c5c7d4abb5191db7b8355b8904")
            print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "fuzz_cups", aggregate=True, debug_mode=True, include_seeds_metadata=True, parser=C_LineCoverageParser_LLVMCovHTML()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)

        md5s = []
        r = list(res)
        r.sort()
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
        if md5_res != "35ebe7f22d9740b418610d9d4dd81bb7":
            print(f"MD5 of result is {md5_res}, expected 35ebe7f22d9740b418610d9d4dd81bb7")
            print(f"Results from coverage: {res}")
            assert False


        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        md5s = []
        r = list(res)
        r.sort()
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
        if md5_res != "35ebe7f22d9740b418610d9d4dd81bb7":
            print(f"MD5 of result is {md5_res}, expected 35ebe7f22d9740b418610d9d4dd81bb7")
            print(f"Results from coverage: {res}")
            assert False


print("Test: test_covguy_not_aggregate_simple_parser")
test_covguy_not_aggregate_simple_parser()
print("Test: test_covguy_aggregate_simple_parser")
test_covguy_aggregate_simple_parser()
print("Test: test_covguy_aggregate_line_parser")
test_covguy_aggregate_line_parser()
print("Test: test_covguy_not_aggregate_line_parser")
test_covguy_not_aggregate_line_parser()

print("*******All tests passed!*******")